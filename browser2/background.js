
// chrome.storage.local.clear(() => {
//   console.log("All local storage data cleared.");
// });
chrome.storage.local.remove("rsaPublicKey", () => {
 // console.log("RSA 公钥已删除");
});
chrome.storage.local.remove("privateKey", () => {
  //console.log("RSA 私钥已删除");
});

let serverUrl = "";
//标识浏览器id
const clientId = self.crypto.randomUUID();

let publicKey = "";
let privateKey="";
let publicKeyVerify="";
let sseErrorCount = 0;
let errorMsg="";
// 处理来自内容脚本的消息
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // console.log("sender",message.tabid);
  switch (message.type) {
    case 'GET_ERROR':
      sendResponse({status:0,data:errorMsg});
    break;
    case 'GET_URL':

      sendResponse({ status: 0 });
      //console.log("收到内容脚本的 URL:", message.url);
      //serverUrl=message.url;
      break;
    case 'close_tab':
      chrome.tabs.remove(sender.tab.id);
      break;

    case 'START_FETCH':

      if (serverUrl !== "" && isValidUrl(serverUrl)) {

        if (!message.tabid) {
          message.tabid=sender.tab.id;
        }

        chrome.tabs.get(message.tabid, (tab) => {
          if (chrome.runtime.lastError) {
            console.log('Tab no longer exists');
            showBadge("error","red");
            showMsgPopup('Tab no longer exists');
          } 
          else 
          {
            console.log('Tab exists');
            console.log('START_FETCH:');
            //请求cry，发送密钥
            console.log("SEND_CRY");
            // 加密 AES 密钥，并将加密后的数据发送到服务器
            const aesKey = getAESKey();

            encryptAESKey(aesKey, publicKey).then(encryptedAES => {
              //console.log(encryptedAES);

              const url = `${serverUrl}cry?clientid=${clientId}`;

              fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ Key: encryptedAES })
              })
                .then(response => response.ok)
                .then( result => {
                  if (result) {
                    const sseurl = `${serverUrl}sse?tabid=${message.tabid}&clientid=${clientId}`;
                    // 使用
                    const client = new SSEClient(sseurl);
                    const eventSource = client.connect();
                    //const eventSource=eventCon.instance;

                    if (!eventSource) {
                      console.log("SSE 429");
                      return;
                    }
                    // 监听消息
                    eventSource.onmessage =async (e) => {
                      const base64data = e.data;//JSON.parse(e.data);
                      //console.log('收到消息:', base64data);
                      //如果收到的是纯数字忽略，如果是base64,将数据发送到指定的tab进行解密
                      if (!isBase64(base64data)) {
                        //todo: 这里可以做 通知，例如指示灯 表示 一直在保持连接
                        startBlinkingBadge();
                        //console.log('收到消息:', base64data);
                        return;
                      }

                      //解开base64 获取 clientid 和 tabid，
                      var data = base64ToString(base64data);
                      var jsonData = JSON.parse(data);
                      //验证数据
                      if (jsonData.clientId !== clientId) {
                        console.log('client id error', jsonData.clientId);
                        showBadge("error","red");
                        showMsgPopup('client id error');
                        return;
                      }

                      //解密数据
                      const payload=jsonData.data;
                      // 1. 解密 AES 密钥（使用客户端私钥 A）
                      const encryptedAesKeyBuffer = base64ToArrayBuffer(payload.AESKey);
                      const aesKeyBuffer =await crypto.subtle.decrypt(
                          { name: "RSA-OAEP", hash: "SHA-256" },
                          privateKey, // 预先导入的 RSA 私钥（CryptoKey 对象）
                          encryptedAesKeyBuffer
                      );

                      // 2. 导入 AES 密钥
                      const aesKey = await crypto.subtle.importKey(
                          "raw",
                          aesKeyBuffer,
                          { name: "AES-GCM" },
                          false,
                          ["decrypt"]
                      );

                        // 3. 解密 SSE 消息（AES-GCM）  
                      const iv = new Uint8Array(base64ToArrayBuffer(payload.IV));
                      const ciphertext = new Uint8Array(base64ToArrayBuffer(payload.Encrypted));
                      const tag = new Uint8Array(base64ToArrayBuffer(payload.Tag));

                      // 在 Web Crypto API 中，AES-GCM 需要将 tag 附加在密文后面
                      const encryptedData = new Uint8Array(ciphertext.length + tag.length);
                      encryptedData.set(ciphertext);
                      encryptedData.set(tag, ciphertext.length);

                      const decryptedBuffer = await crypto.subtle.decrypt(
                          { name: "AES-GCM", iv: iv },
                          aesKey,
                          encryptedData
                      );

                      const decoder = new TextDecoder();
                      const plaintext = decoder.decode(decryptedBuffer);
                     // console.log("Decrypted message:", plaintext);

                         // 4. 验证数字签名（使用服务器公钥 B）
                      // 将密文作为签名验证数据（此处示例仅验证加密后的消息数据）
                      const signatureBuffer = base64ToArrayBuffer(payload.Signature);
                      const isValid = await crypto.subtle.verify(
                          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                          publicKeyVerify, // 预先导入的服务器公钥（CryptoKey 对象，用于签名验证）
                          signatureBuffer,
                          ciphertext // 签名验证数据需与服务器签名时一致
                      );

                      if (!isValid) {
                        //todo: 此处可以 发消息，页面弹出提示 数据异常
                        console.error("Signature invalid!");
                        showBadge("error","red");
                        showMsgPopup('Signature invalid!');
                        return;
                      }
                  
                      //发送填充
                      const tabId = parseInt(jsonData.tabId, 10);
                      const msgdata = { type: 'FILL_DATA', data: plaintext };
                      console.log('tabId:', tabId);

                      chrome.tabs.sendMessage(tabId, msgdata, (response) => {
                        if (chrome.runtime.lastError) {
                          console.error("Error sending message:", chrome.runtime.lastError.message);
                          showMsgPopup('Error sending message');
                        } else {
                          console.log("Message sent successfully:", response);
                        }
                      });
                    };

                    // 错误处理
                    eventSource.onerror = (err) => {
                      console.error('SSE连接错误:', err);
                      showBadge("error","red");
                      showMsgPopup('SSE connection error');
                      sseErrorCount++;

                      if (sseErrorCount > 5) {
                        client.disconnect();
                      }
                      // 自动重连逻辑
                      // setTimeout(() => {
                      //     eventSource = new EventSource(url);
                      // }, 5000);
                    };
                  }
                  else {
                    console.log("send cry failed");
                    showBadge("error","red");
                    showMsgPopup('send cry failed');
                  }
                });
            });

            //chrome.tabs.sendMessage(message.tabid, { type: 'START_FETCH', url: serverUrl, tabid: message.tabid });
            //这里可以增加 通知 tab页面
          }
        })
      }
      else {
        console.log("无效的URL:", serverUrl);
      }

      break;

    default:
      break;
  }

  return true; // 让 sendResponse 在异步回调里生效
});

//拦截请求
chrome.webRequest.onHeadersReceived.addListener(p => {

  const regex = /^http:\/\/(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}):9\d{3}\/?$/;
  const isLanIP = regex.test(p.url);

  if (!isLanIP) {
    return { responseHeaders: p.responseHeaders };
  }

  const headers = p.responseHeaders;
  const passHeader = headers.find(header => header.name.toLowerCase() === "pass");
  const passbHeader = headers.find(header => header.name.toLowerCase() === "passb");

  if (passHeader && passbHeader) {

    serverUrl = p.url;

    const passValue = passHeader.value;
    const passBValue = passbHeader.value;
    //base64 to xml
    const xmlpublicKey = new TextDecoder().decode(Uint8Array.from(atob(passValue), c => c.charCodeAt(0)));
    const pemprivateKey = new TextDecoder().decode(Uint8Array.from(atob(passBValue), c => c.charCodeAt(0)));

    importRsaPublicKey(xmlpublicKey).then(cryptoKey => {
      //console.log("成功导入 RSA 公钥:", cryptoKey);
      publicKey = cryptoKey;
    })
      .catch(error => {
        console.error("导入 RSA 公钥失败:", error);
        showBadge("error","red");
        showMsgPopup('import PublicKey failed');
      });

      importRsaPublicKeyForVerify(xmlpublicKey).then(cryptoKey => {
        //console.log("成功导入 RSA 公钥:", cryptoKey);
        publicKeyVerify = cryptoKey;
      })
        .catch(error => {
          console.error("导入 RSA 公钥失败:", error);
          showBadge("error","red");
          showMsgPopup('import PublicKey failed');
        });
    importClientPrivateKey(pemprivateKey).then(cryptoKey => {
      //console.log("客户端私钥已成功导入：", cryptoKey);
      privateKey=cryptoKey;
    })
      .catch(error => {
        console.error("导入客户端私钥失败：", error);
        showBadge("error","red");
        showMsgPopup('import privateKey failed');
      });

    // 过滤掉 pass 和 passb 这两个 header
    //  const modifiedHeaders = details.responseHeaders.filter(header => {
    //   const headerName = header.name.toLowerCase();
    //   return headerName !== "pass" && headerName !== "passb";
    // });

    // // 返回修改后的 header 数组
    // return { responseHeaders: modifiedHeaders };
  }
  else {
    console.log("header no pass");

  }
}, {
  urls: ["http://*/*"]
},
  ["responseHeaders"]);


  function showMsgPopup(data) {
    errorMsg=data;
    //chrome.runtime.sendMessage({type:'msg' ,data});
  }
//通用方法
/**
 * 开始闪烁
 * @param {string} text - 要显示的徽章文本（例如 "!"）
 * @param {number} interval - 闪烁间隔（毫秒）
 */
function startBlinkingBadge(text = "!", interval = 1000) {
  // 如果已经在闪烁，先停止
  showBadge(text);

  blinkIntervalId = setInterval(() => {
    chrome.action.setBadgeText({ text: "" });

    if (blinkIntervalId) {
      clearInterval(blinkIntervalId);
      blinkIntervalId = null;
    }
  }, interval);
}

function showBadge(text,color="#008000") {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color }); // 绿色背景
}

function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}


function base64ToString(data) {
  return new TextDecoder().decode(Uint8Array.from(atob(data), c => c.charCodeAt(0)));
}

// 2. 将标准 Base64 转换为 Base64url 格式（去掉末尾 "=" 并替换 "+"、"/"）
function base64ToBase64Url(base64Str) {
  return base64Str
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function isValidUrl(url) {
  try {
    new URL(url);  // 如果 URL 格式正确，不会抛出错误
    return true;
  } catch (e) {
    return false;
  }
}

function uint8ArrayToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function getAESKey() {
  // 生成 256 位（32 字节）的密钥
  const keyArray = new Uint8Array(32);
  crypto.getRandomValues(keyArray);
  //console.log("随机密钥（Uint8Array）：", keyArray);

  // 将密钥转换为 Base64 字符串
  const base64Key = uint8ArrayToBase64(keyArray);
  //console.log("随机密钥（Base64）：", base64Key);
  return base64Key;
}


// 假设你已经将公钥转换为合适格式，并成功导入 Web Crypto API 的 RSA 公钥对象
async function encryptAESKey(aesKeyStr, rsaPublicKey) {
  // 创建文本编码器，将字符串转换为 Uint8Array（二进制数据）
  const encoder = new TextEncoder();
  const aesKeyBuffer = encoder.encode(aesKeyStr);

  // 使用 Web Crypto API 的 RSA-OAEP 算法加密 AES 密钥
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" }  // 指定加密算法及填充方式，RSA-OAEP 是推荐使用的方式
    },
    rsaPublicKey,  // 已经导入的 RSA 公钥对象
    aesKeyBuffer   // 待加密的数据（这里是 AES 密钥的二进制表示）
  );

  // 将加密后的 ArrayBuffer 转换为 Base64 字符串，以便于通过 JSON 或其他文本传输方式发送到服务器
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function importRsaPublicKey(xmlKey) {

  // 使用正则表达式提取 Modulus 和 Exponent
  const modulus = xmlKey.match(/<Modulus>(.*?)<\/Modulus>/)[1];
  const exponent = xmlKey.match(/<Exponent>(.*?)<\/Exponent>/)[1];
  // 构造 JWK 对象
  const jwkKey = {
    kty: "RSA",
    n: base64ToBase64Url(modulus),
    e: base64ToBase64Url(exponent),
    alg: "RSA-OAEP-256", // 算法可以根据实际情况设置，如 RSA-OAEP-256（对应 SHA-256）
    ext: false,           // 是否允许导出密钥，根据需要设为 true 或 false
  };

  //console.log("JWK Key:", jwkKey);

  // 3. 导入公钥
  const publicKey2 = crypto.subtle.importKey(
    "jwk",           // 导入格式为 JWK
    jwkKey,          // JWK 对象
    {
      name: "RSA-OAEP", // 加密算法，这里采用 RSA-OAEP
      hash: "SHA-256",  // 指定哈希算法
    },
    false,            // 是否允许导出，取决于业务需求
    ["encrypt"]      // 允许的用途（例如仅用于加密，或根据需要包含 "verify"）
  );

  // 将 JWK 格式公钥存储到 Chrome Storage
  chrome.storage.local.set({ rsaPublicKey: jwkKey }, () => {
   // console.log("RSA 公钥已存储到 Chrome Storage");
  });

  return publicKey2;
}

async function importRsaPublicKeyForVerify(xmlKey) {

  // 使用正则表达式提取 Modulus 和 Exponent
  const modulus = xmlKey.match(/<Modulus>(.*?)<\/Modulus>/)[1];
  const exponent = xmlKey.match(/<Exponent>(.*?)<\/Exponent>/)[1];
  // 构造 JWK 对象
  const jwkKey = {
    kty: "RSA",
    n: base64ToBase64Url(modulus),
    e: base64ToBase64Url(exponent),
   // alg: "RSA-OAEP-256", // 算法可以根据实际情况设置，如 RSA-OAEP-256（对应 SHA-256）
    ext: false,           // 是否允许导出密钥，根据需要设为 true 或 false
  };

  //console.log("JWK Key:", jwkKey);
  const { alg, ...jwkWithoutAlg } = jwkKey;
  // 3. 导入公钥
  return crypto.subtle.importKey(
    "jwk",           // 导入格式为 JWK
    jwkWithoutAlg,          // JWK 对象
    {
      name: "RSASSA-PKCS1-v1_5", // 加密算法，这里采用 RSA-OAEP
      hash: "SHA-256",  // 指定哈希算法
    },
    false,            // 是否允许导出，取决于业务需求
    ["verify"]      // 允许的用途（例如仅用于加密，或根据需要包含 "verify"）
  );
}

async function getStoredRsaPublicKey() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get("rsaPublicKey", async (result) => {
      if (!result.rsaPublicKey) {
        reject("未找到存储的 RSA 公钥");
        return;
      }

      try {
        // 重新导入存储的公钥
        const publicKey = await crypto.subtle.importKey(
          "jwk",
          result.rsaPublicKey,
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["encrypt"]
        );
        resolve(publicKey);
      } catch (error) {
        reject("导入公钥失败: " + error);
      }
    });
  });
}

// // 调用示例
// getStoredRsaPublicKey().then((publicKey) => {
//   console.log("成功获取存储的 RSA 公钥:", publicKey);
// }).catch(console.error);


function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}


/**
 * 将 PEM 格式的字符串转换为 ArrayBuffer
 * @param {string} pem - PEM 格式的密钥字符串
 * @returns {ArrayBuffer}
 */
function pemToArrayBuffer(pem) {
  // 去掉头尾信息和换行符
  const b64Lines = pem.replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  // Base64 解码为二进制字符串
  const binaryString = atob(b64Lines);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
* 导入 PEM 格式的 RSA 私钥，并返回 CryptoKey 对象
* @param {string} pemKey - PEM 格式的 RSA 私钥
* @returns {Promise<CryptoKey>}
*/
async function importClientPrivateKey(pemKey) {
  const keyBuffer = pemToArrayBuffer(pemKey);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",               // 私钥导入格式
    keyBuffer,             // 包含私钥 DER 数据的 ArrayBuffer
    {
      name: "RSA-OAEP",  // 使用的算法名称
      hash: "SHA-256"    // 使用的哈希算法
    },
    true,                  // 是否可导出（根据需要，可设为 false）
    ["decrypt"]            // 私钥用途，这里用于解密
  );

  const exportedJwk = await crypto.subtle.exportKey("jwk", cryptoKey);
  chrome.storage.local.set({ privateKey: exportedJwk }, () => {
    //console.log("RSA 私钥已存储到 Chrome Storage");
  });

  return cryptoKey;
}

async function getStoredPrivateKey() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get("privateKey", async (result) => {
      if (!result.privateKey) {
        reject("未找到存储的 RSA 私钥");
        return;
      }
      try {
        // 重新导入 JWK 私钥
        const privateKey = await crypto.subtle.importKey(
          "jwk",
          result.privateKey,
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["decrypt"]
        );
        resolve(privateKey);
      } catch (error) {
        reject("导入私钥失败: " + error);
      }
    });
  });
}


function isNumber(value) {
  return !isNaN(value) && typeof value === 'number';
}

function isBase64(str) {
  const base64Regex = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
  return base64Regex.test(str);
}

//定期执行，保持活动
chrome.alarms.create('myAlarm', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'myAlarm') {
    console.log('Alarm triggered, background script is active');
  }
});



class SSEClient {
  constructor(url) {
    this.url = url;
    this.instance = null;
  }

   async checkServerAvailability() {
    try {
        const response = await fetch(this.url, { method: "HEAD" }); // 仅检查服务器状态
        if (response.status === 429) {
            console.warn("请求过多，稍后重试...");
            return false;
        }
        return true;
    } catch (error) {
        console.error("服务器无法访问:", error);
        return false;
    }
}

   connect() {
    if (this.instance && this.instance.readyState !== EventSource.CLOSED) {
      console.log("已有活动连接，忽略请求");
      return this.instance;
    }

    // const available = await this.checkServerAvailability();
    // if (!available) return null;
    
    if (!this.instance) {
      this.instance = new EventSource(this.url);
      this.instance.onerror = (e) => {
        if (e.eventPhase === EventSource.CLOSED) {
          this.reconnect();
        }
      };
    }

    return this.instance;
  }

  disconnect() {
    if (this.instance) {
      this.instance.close();
      this.instance = null;
    }
  }

  reconnect() {
    this.disconnect();
    this.connect();
  }
}