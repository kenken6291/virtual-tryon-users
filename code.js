/**
 * ===== セキュリティ設計メモ =====
 * 1. APIキー・APP_TOKEN・USERS_SHEET_ID等の秘匿情報は全てPropertiesServiceで管理し、
 *    コードには一切ハードコーディングしない。
 * 2. 認証: スプレッドシート「Users」にusername/passwordHash/saltを保存し、
 *    平文パスワードは一切保存・ログ出力しない（SHA-256 + salt）。
 * 3. ログイン成功時にセッショントークンを発行し、CacheServiceで有効期限管理する
 *    （サーバー側で自動失効するため、盗用されても長期間悪用されにくい）。
 * 4. try-on実行時は「APP_TOKEN（アプリ簡易フィルタ）」と「セッショントークン（個人認証）」の
 *    二重チェックを行う（多層防御）。
 * 5. ★画像データ（自分の写真・服の写真・生成結果）はGoogleドライブ等への保存を一切行わず、
 *    関数内のメモリ上（変数）でのみ処理し、レスポンス返却後は自動的に破棄される。
 *    ログ出力時も画像本体は絶対に出力しない。
 */

const PROP_KEYS = {
  APP_TOKEN: 'APP_TOKEN',
  TRYON_API_KEY: 'TRYON_API_KEY',
  TRYON_API_URL: 'TRYON_API_URL',
  USERS_SHEET_ID: 'USERS_SHEET_ID',
  SESSION_TTL_SEC: 'SESSION_TTL_SEC'
};

const DEFAULT_TRYON_API_URL = 'https://api.example.com/v1/try-on';
const DEFAULT_SESSION_TTL_SEC = 1800; // 30分
const USERS_SHEET_NAME = 'Users'; // ヘッダー: username | passwordHash | salt | displayName

/**
 * GET: Webアプリのエントリーポイント。Index.htmlを返す。
 */
function doGet(e) {
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('Virtual Try-On')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/**
 * POST: actionフィールドに応じて処理を振り分ける。
 * - action: "login" → 認証してセッショントークンを発行
 * - action: "tryon" → 試着画像生成（要セッショントークン）
 */
function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return createJsonResponse_(false, null, 'リクエストボディが空です。');
    }

    let requestBody;
    try {
      requestBody = JSON.parse(e.postData.contents);
    } catch (parseErr) {
      return createJsonResponse_(false, null, 'リクエストの形式が不正です。');
    }

    // --- 共通: アプリ簡易トークンの検証（多層防御の1層目） ---
    const scriptProps = PropertiesService.getScriptProperties();
    const validAppToken = scriptProps.getProperty(PROP_KEYS.APP_TOKEN);
    if (!validAppToken) {
      console.error('APP_TOKEN が未設定です。');
      return createJsonResponse_(false, null, 'サーバー設定エラーです。', 500);
    }
    if (requestBody.appToken !== validAppToken) {
      console.warn('不正なappTokenによるアクセスを検知しました。');
      return createJsonResponse_(false, null, '認証に失敗しました。', 403);
    }

    const action = requestBody.action;
    if (action === 'login') {
      return handleLogin_(requestBody, scriptProps);
    } else if (action === 'tryon') {
      return handleTryOn_(requestBody, scriptProps);
    } else {
      return createJsonResponse_(false, null, '不明なアクションです。', 400);
    }

  } catch (unexpectedErr) {
    console.error('doPost 予期しないエラー: ' + unexpectedErr.message);
    return createJsonResponse_(false, null, 'サーバー内部でエラーが発生しました。', 500);
  }
}

/**
 * ログイン処理。
 * 期待するpayload: { action:'login', appToken, username, password }
 */
function handleLogin_(payload, scriptProps) {
  const username = (payload.username || '').trim();
  const password = payload.password || '';

  if (!username || !password) {
    return createJsonResponse_(false, null, 'ユーザー名とパスワードを入力してください。', 400);
  }

  const usersSheetId = scriptProps.getProperty(PROP_KEYS.USERS_SHEET_ID);
  if (!usersSheetId) {
    console.error('USERS_SHEET_ID が未設定です。');
    return createJsonResponse_(false, null, 'サーバー設定エラーです。', 500);
  }

  let sheet;
  try {
    sheet = SpreadsheetApp.openById(usersSheetId).getSheetByName(USERS_SHEET_NAME);
  } catch (err) {
    console.error('Usersシートを開けませんでした: ' + err.message);
    return createJsonResponse_(false, null, 'サーバー設定エラーです。', 500);
  }
  if (!sheet) {
    console.error('シート「' + USERS_SHEET_NAME + '」が見つかりません。');
    return createJsonResponse_(false, null, 'サーバー設定エラーです。', 500);
  }

  const data = sheet.getDataRange().getValues(); // [0]行目はヘッダー想定
  let matchedRow = null;
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim() === username) {
      matchedRow = data[i];
      break;
    }
  }

  // ユーザーが存在しない場合も、存在する場合と同じ処理時間・同じエラーメッセージにすることで
  // 「ユーザー存在の有無」が外部から推測されにくいようにする（ユーザー列挙攻撃対策）
  const dummySalt = 'dummy_salt_for_timing';
  const dummyHash = 'dummy_hash';
  const salt = matchedRow ? String(matchedRow[2]) : dummySalt;
  const storedHash = matchedRow ? String(matchedRow[1]) : dummyHash;

  const inputHash = hashPassword_(password, salt);

  if (!matchedRow || inputHash !== storedHash) {
    console.warn('ログイン失敗: username=' + username);
    return createJsonResponse_(false, null, 'ユーザー名またはパスワードが正しくありません。', 401);
  }

  // --- セッショントークン発行 ---
  const sessionToken = Utilities.getUuid();
  const ttlSec = parseInt(scriptProps.getProperty(PROP_KEYS.SESSION_TTL_SEC), 10) || DEFAULT_SESSION_TTL_SEC;

  const cache = CacheService.getScriptCache();
  // CacheServiceの最大有効期限は21600秒(6時間)。ttlSecがそれを超える場合は丸める。
  const safeTtl = Math.min(ttlSec, 21600);
  cache.put('session_' + sessionToken, username, safeTtl);

  const displayName = matchedRow[3] || username;

  return createJsonResponse_(true, {
    sessionToken: sessionToken,
    displayName: displayName,
    expiresInSec: safeTtl
  }, null);
}

/**
 * 試着画像生成処理（要セッショントークン）。
 * 期待するpayload: { action:'tryon', appToken, sessionToken, modelImageBase64, clothImageBase64 }
 * ★画像はDrive等に保存せず、この関数のスコープ内でのみ扱い、
 *   レスポンス返却と同時に変数は破棄される（ガベージコレクション対象）。
 */
function handleTryOn_(payload, scriptProps) {
  // --- セッショントークンの検証（多層防御の2層目：個人認証） ---
  const sessionToken = payload.sessionToken;
  if (!sessionToken) {
    return createJsonResponse_(false, null, 'ログインが必要です。', 401);
  }

  const cache = CacheService.getScriptCache();
  const username = cache.get('session_' + sessionToken);
  if (!username) {
    return createJsonResponse_(false, null, 'セッションが無効です。再ログインしてください。', 401);
  }

  const modelImageBase64 = payload.modelImageBase64;
  const clothImageBase64 = payload.clothImageBase64;

  if (!modelImageBase64 || !clothImageBase64) {
    return createJsonResponse_(false, null, '画像データが不足しています。', 400);
  }

  const MAX_BASE64_LENGTH = 14 * 1024 * 1024; // 約10MBの画像相当（Base64は約1.37倍）
  if (modelImageBase64.length > MAX_BASE64_LENGTH || clothImageBase64.length > MAX_BASE64_LENGTH) {
    return createJsonResponse_(false, null, '画像サイズが大きすぎます。', 400);
  }

  const tryonApiKey = scriptProps.getProperty(PROP_KEYS.TRYON_API_KEY);
  if (!tryonApiKey) {
    console.error('TRYON_API_KEY が未設定です。');
    return createJsonResponse_(false, null, 'サーバー設定エラーです。', 500);
  }
  const tryonApiUrl = scriptProps.getProperty(PROP_KEYS.TRYON_API_URL) || DEFAULT_TRYON_API_URL;

  const externalPayload = {
    model_image: modelImageBase64,
    cloth_image: clothImageBase64
    // 外部APIの仕様に応じてパラメータを追加（例: category, resolutionなど）
  };

  const fetchOptions = {
    method: 'post',
    contentType: 'application/json',
    headers: {
      // 認証キーはヘッダー経由で送信し、ログ等に平文で残らないよう配慮
      'Authorization': 'Bearer ' + tryonApiKey
    },
    payload: JSON.stringify(externalPayload),
    muteHttpExceptions: true // エラーレスポンスも自前でハンドリングするため
  };

  let externalResponse;
  try {
    externalResponse = UrlFetchApp.fetch(tryonApiUrl, fetchOptions);
  } catch (fetchErr) {
    console.error('外部API呼び出しで通信エラー: ' + fetchErr.message);
    return createJsonResponse_(false, null, '外部サービスとの通信に失敗しました。時間をおいて再度お試しください。', 502);
  }

  const statusCode = externalResponse.getResponseCode();
  const responseText = externalResponse.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    console.error('外部API エラー user=' + username + ' status=' + statusCode);
    return createJsonResponse_(false, null, '試着画像の生成に失敗しました（外部サービスエラー）。', 502);
  }

  let externalResult;
  try {
    externalResult = JSON.parse(responseText);
  } catch (parseErr) {
    console.error('外部APIレスポンスのJSONパースに失敗しました。');
    return createJsonResponse_(false, null, '試着画像の生成結果を解析できませんでした。', 502);
  }

  // 外部APIのレスポンス構造に合わせて調整すること（ここでは result_image_base64 と仮定）
  const resultImageBase64 = externalResult.result_image_base64;
  if (!resultImageBase64) {
    return createJsonResponse_(false, null, '試着画像が生成されませんでした。', 502);
  }

  // 監査用ログは「誰が使ったか」程度に留め、画像本体は絶対にログしない
  console.log('try-on success user=' + username);

  // --- 結果を即時返却。ここで扱った画像変数（modelImageBase64等）はどこにも保存せず、
  //     この関数のスコープを抜けると同時にGCの対象となり破棄される。 ---
  return createJsonResponse_(true, { resultImageBase64: resultImageBase64 }, null);
}

/**
 * パスワードのハッシュ化（SHA-256 + salt）。
 * 本番運用でさらに強度を上げたい場合は、GASの範囲では限界があるため
 * 外部の認証基盤（Firebase Auth等）への移行を検討すること。
 */
function hashPassword_(password, salt) {
  const rawBytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    salt + password,
    Utilities.Charset.UTF_8
  );
  return rawBytes.map(b => (b < 0 ? b + 256 : b).toString(16).padStart(2, '0')).join('');
}

/**
 * 新規スタッフ登録用のヘルパー関数。
 * GASエディタから直接実行して、Usersシートに1行追加する運用を想定。
 * （フロントエンドからは呼び出せない = 管理者のみが実行可能）
 * 使い方: 実行後は平文パスワードを書いたこの呼び出しコードを削除すること。
 *
 * 例: addUser_ManualRunOnly('staff01', '初期パスワード', '店舗スタッフA');
 */
function addUser_ManualRunOnly(username, plainPassword, displayName) {
  const scriptProps = PropertiesService.getScriptProperties();
  const usersSheetId = scriptProps.getProperty(PROP_KEYS.USERS_SHEET_ID);
  const sheet = SpreadsheetApp.openById(usersSheetId).getSheetByName(USERS_SHEET_NAME);

  const salt = Utilities.getUuid();
  const passwordHash = hashPassword_(plainPassword, salt);

  sheet.appendRow([username, passwordHash, salt, displayName || username]);
  Logger.log('ユーザーを追加しました: ' + username);
}

/**
 * JSON形式のレスポンスを生成する共通関数。
 */
function createJsonResponse_(success, data, errorMessage, httpStatus) {
  const body = {
    success: success,
    httpStatus: httpStatus || (success ? 200 : 400)
  };
  if (data) {
    Object.assign(body, data);
  }
  if (errorMessage) {
    body.message = errorMessage;
  }
  return ContentService
    .createTextOutput(JSON.stringify(body))
    .setMimeType(ContentService.MimeType.JSON);
}