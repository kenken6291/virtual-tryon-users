/**
 * ===== セキュリティ設計メモ =====
 * 1. APIキー・APP_TOKEN・USERS_SHEET_ID等の秘匿情報は全てPropertiesServiceで管理し、
 *    コードには一切ハードコーディングしない。
 * 2. 認証: スプレッドシート「Users」にusername/passwordHash/saltを保存し、
 *    平文パスワードは一切保存・ログ出力しない（SHA-256 + salt）。
 * 3. ログイン成功時にセッショントークンを発行し、CacheServiceで有効期限管理する。
 * 4. try-on実行時は「APP_TOKEN（アプリ簡易フィルタ）」と「セッショントークン（個人認証）」の
 *    二重チェックを行う（多層防御）。
 * 5. ★画像データ（自分の写真・服の写真・生成結果）はGoogleドライブ等への保存を一切行わず、
 *    関数内のメモリ上（変数）でのみ処理し、レスポンス返却後は自動的に破棄される。
 *    ログ出力時も画像本体は絶対に出力しない。
 */

const PROP_KEYS = {
  APP_TOKEN: 'APP_TOKEN',
  TRYON_API_KEY: 'TRYON_API_KEY',
  USERS_SHEET_ID: 'USERS_SHEET_ID',
  SESSION_TTL_SEC: 'SESSION_TTL_SEC'
};

const DEFAULT_SESSION_TTL_SEC = 1800; // 30分
const USERS_SHEET_NAME = 'Users'; // ヘッダー: username | passwordHash | salt | displayName
const LIGHTX_BASE_URL = 'https://api.lightxeditor.com/external/api';

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

  const data = sheet.getDataRange().getValues();
  let matchedRow = null;
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim() === username) {
      matchedRow = data[i];
      break;
    }
  }

  // ユーザー列挙攻撃対策: 存在しない場合もダミー値で同じ処理時間・同じエラーメッセージにする
  const dummySalt = 'dummy_salt_for_timing';
  const dummyHash = 'dummy_hash';
  const salt = matchedRow ? String(matchedRow[2]) : dummySalt;
  const storedHash = matchedRow ? String(matchedRow[1]) : dummyHash;
  const inputHash = hashPassword_(password, salt);

  if (!matchedRow || inputHash !== storedHash) {
    console.warn('ログイン失敗: username=' + username);
    return createJsonResponse_(false, null, 'ユーザー名またはパスワードが正しくありません。', 401);
  }

  const sessionToken = Utilities.getUuid();
  const ttlSec = parseInt(scriptProps.getProperty(PROP_KEYS.SESSION_TTL_SEC), 10) || DEFAULT_SESSION_TTL_SEC;
  const cache = CacheService.getScriptCache();
  const safeTtl = Math.min(ttlSec, 21600); // CacheServiceの上限は21600秒(6時間)
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
 * 期待するpayload: { action:'tryon', appToken, sessionToken,
 *                     modelFrontImageBase64, modelSideImageBase64, clothImageBase64,
 *                     garmentType }
 * ★画像はDrive等に保存せず、この関数のスコープ内でのみ扱い、
 *   レスポンス返却と同時に変数は破棄される（ガベージコレクション対象）。
 */
function handleTryOn_(payload, scriptProps) {
  const sessionToken = payload.sessionToken;
  if (!sessionToken) {
    return createJsonResponse_(false, null, 'ログインが必要です。', 401);
  }
  const cache = CacheService.getScriptCache();
  const username = cache.get('session_' + sessionToken);
  if (!username) {
    return createJsonResponse_(false, null, 'セッションが無効です。再ログインしてください。', 401);
  }

  const modelFrontImageBase64 = payload.modelFrontImageBase64;
  const modelSideImageBase64 = payload.modelSideImageBase64;
  const clothImageBase64 = payload.clothImageBase64;
  const garmentType = payload.garmentType || 'shirt'; // 'shirt' | 'jacket' | 'bottom' | 'dress'

  if (!modelFrontImageBase64 || !modelSideImageBase64 || !clothImageBase64) {
    return createJsonResponse_(false, null, '画像データが不足しています。', 400);
  }

  const MAX_BASE64_LENGTH = 14 * 1024 * 1024; // 約10MBの画像相当
  if (modelFrontImageBase64.length > MAX_BASE64_LENGTH ||
      modelSideImageBase64.length > MAX_BASE64_LENGTH ||
      clothImageBase64.length > MAX_BASE64_LENGTH) {
    return createJsonResponse_(false, null, '画像サイズが大きすぎます。', 400);
  }

  const apiKey = scriptProps.getProperty(PROP_KEYS.TRYON_API_KEY);
  if (!apiKey) {
    console.error('TRYON_API_KEY が未設定です。');
    return createJsonResponse_(false, null, 'サーバー設定エラーです。', 500);
  }

  try {
    // ① 3枚の画像をLightXにアップロードしてURL化（服の写真は1回だけアップロードして使い回す）
    const clothImageUrl = uploadImageToLightX_(clothImageBase64, apiKey);
    const frontImageUrl = uploadImageToLightX_(modelFrontImageBase64, apiKey);
    const sideImageUrl = uploadImageToLightX_(modelSideImageBase64, apiKey);

    // ② 正面・横向き、それぞれの生成リクエストを発行
    const orderIds = {
      front: submitLightXOrder_(frontImageUrl, clothImageUrl, apiKey, garmentType),
      side: submitLightXOrder_(sideImageUrl, clothImageUrl, apiKey, garmentType)
    };

    // ③ 両方の結果が揃うまでまとめてポーリング
    const resultUrls = pollLightXOrders_(orderIds, apiKey);

    // ④ 結果画像をダウンロードしてBase64に変換（フロントの表示ロジックのため）
    const resultFrontImageBase64 = fetchImageAsBase64_(resultUrls.front);
    const resultSideImageBase64 = fetchImageAsBase64_(resultUrls.side);

    console.log('try-on success user=' + username + ' garmentType=' + garmentType);
    return createJsonResponse_(true, {
      resultFrontImageBase64: resultFrontImageBase64,
      resultSideImageBase64: resultSideImageBase64
    }, null);

  } catch (err) {
    console.error('LightX処理エラー user=' + username + ' message=' + err.message);
    return createJsonResponse_(false, null, '試着画像の生成に失敗しました。時間をおいて再度お試しください。', 502);
  }
}

/**
 * LightX用: 画像1枚をアップロードしてURLを取得する。
 * ①アップロードURL取得 → ②PUTでバイナリアップロード、の2段階。
 */
function uploadImageToLightX_(base64DataUrl, apiKey) {
  const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.*)$/.exec(base64DataUrl);
  const contentType = match ? match[1] : 'image/jpeg';
  const base64Data = match ? match[2] : base64DataUrl;
  const decodedBytes = Utilities.base64Decode(base64Data);

  const uploadUrlResponse = UrlFetchApp.fetch(LIGHTX_BASE_URL + '/v2/uploadImageUrl', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'x-api-key': apiKey },
    payload: JSON.stringify({
      uploadType: 'imageUrl',
      size: decodedBytes.length,
      contentType: contentType
    }),
    muteHttpExceptions: true
  });

  const uploadUrlResult = JSON.parse(uploadUrlResponse.getContentText());
  const uploadImageTarget = uploadUrlResult.body ? uploadUrlResult.body.uploadImage : uploadUrlResult.uploadImage;
  const finalImageUrl = uploadUrlResult.body ? uploadUrlResult.body.imageUrl : uploadUrlResult.imageUrl;

  if (!uploadImageTarget || !finalImageUrl) {
    throw new Error('LightX: アップロードURLの取得に失敗しました。 response=' + uploadUrlResponse.getContentText());
  }

  const putResponse = UrlFetchApp.fetch(uploadImageTarget, {
    method: 'put',
    contentType: contentType,
    payload: Utilities.newBlob(decodedBytes, contentType),
    muteHttpExceptions: true
  });

  if (putResponse.getResponseCode() !== 200) {
    throw new Error('LightX: 画像アップロードに失敗しました。status=' + putResponse.getResponseCode());
  }

  return finalImageUrl;
}

/**
 * LightXへ生成リクエストを1件発行し、orderIdだけを返す（ポーリングはしない）。
 * ※garmentTypeはLightX公式ドキュメントには未記載のパラメータ。
 *   将来的な仕様対応を見越して送信しているが、現時点で結果への影響は未確認。
 */
function submitLightXOrder_(imageUrl, styleImageUrl, apiKey, garmentType) {
  const tryonResponse = UrlFetchApp.fetch(LIGHTX_BASE_URL + '/v2/aivirtualtryon', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'x-api-key': apiKey },
    payload: JSON.stringify({
      imageUrl: imageUrl,
      styleImageUrl: styleImageUrl,
      garmentType: garmentType
    }),
    muteHttpExceptions: true
  });

  const tryonResult = JSON.parse(tryonResponse.getContentText());
  const orderId = tryonResult.body ? tryonResult.body.orderId : tryonResult.orderId;
  if (!orderId) {
    throw new Error('LightX: 生成リクエストの発行に失敗しました。 response=' + tryonResponse.getContentText());
  }
  return orderId;
}

/**
 * 複数のorderIdをまとめてポーリングする。
 * orderIdsMap: { front: 'xxxx', side: 'yyyy' } の形式
 * 戻り値: { front: '結果画像URL', side: '結果画像URL' }
 */
function pollLightXOrders_(orderIdsMap, apiKey) {
  const results = {};
  let pending = Object.keys(orderIdsMap);

  const MAX_POLL_COUNT = 20;
  const POLL_INTERVAL_MS = 3000;

  for (let i = 0; i < MAX_POLL_COUNT && pending.length > 0; i++) {
    Utilities.sleep(POLL_INTERVAL_MS);

    for (let j = pending.length - 1; j >= 0; j--) {
      const key = pending[j];
      const orderId = orderIdsMap[key];

      const statusResponse = UrlFetchApp.fetch(LIGHTX_BASE_URL + '/v1/order-status', {
        method: 'post',
        contentType: 'application/json',
        headers: { 'x-api-key': apiKey },
        payload: JSON.stringify({ orderId: orderId }),
        muteHttpExceptions: true
      });

      const statusResult = JSON.parse(statusResponse.getContentText());
      const body = statusResult.body || statusResult;

      if (body.status === 'active' && body.output) {
        results[key] = body.output;
        pending.splice(j, 1);
      } else if (body.status === 'failed' || body.status === 'FAIL') {
        throw new Error('LightX: 「' + key + '」側の画像生成に失敗しました（外部サービス側エラー）。');
      }
      // それ以外のステータス（init, processingなど）は継続
    }
  }

  if (pending.length > 0) {
    throw new Error('LightX: 生成がタイムアウトしました。時間をおいて再度お試しください。');
  }

  return results;
}

/**
 * 画像URLからバイト列を取得し、Base64のdata URLに変換する。
 */
function fetchImageAsBase64_(imageUrl) {
  const response = UrlFetchApp.fetch(imageUrl, { muteHttpExceptions: true });
  if (response.getResponseCode() !== 200) {
    throw new Error('生成結果画像の取得に失敗しました。');
  }
  const blob = response.getBlob();
  const contentType = blob.getContentType() || 'image/jpeg';
  const base64 = Utilities.base64Encode(blob.getBytes());
  return 'data:' + contentType + ';base64,' + base64;
}

/**
 * パスワードのハッシュ化（SHA-256 + salt）。
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