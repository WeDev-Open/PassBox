
  
const currentUrl = window.location.href;
// 只匹配 192.168.x.x 或 10.x.x.x
//const regex = new RegExp(`^http://(192\\.168\\.\\d{1,3}\\.\\d{1,3}|10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):9\d{3}$`);
const regex = /^http:\/\/(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}):9\d{3}\/?$/;
//console.log(currentUrl);
if (regex.test(currentUrl)) {
    console.log("匹配成功：这是我们要监听的 URL");

    chrome.runtime.sendMessage({ type: 'GET_URL', url: currentUrl }, (response) => {
        console.log("后台返回:", response);
        if (response.status == 0) {
            chrome.runtime.sendMessage({ type: "close_tab" });
        }
        else {
            console.log("后台返回:", response);
        }
    });

} else {
    console.log("当前页面不是目标 URL");
}
  
  const isLogin=isLoginPage();

  // 示例：在内容脚本中使用
  if (isLogin) {
    console.log("当前页面可能是登录页面");
    showPrompt();
    // //登录页面 发消息 连接服务器
    // chrome.runtime.sendMessage({type:'START_FETCH' ,tabid:0});
  } 

  
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
        case 'FILL_DATA':
            //console.log('FILL_DATA:', message);
            sendResponse({ status: 0 }); // 确保调用 sendResponse

            const jsonStr=base64ToString(message.data);
            const json=JSON.parse(jsonStr);
            //console.log("最终数据",json);
            const detectedFields = detectLoginFieldsWithoutForm();
            if (detectedFields) {
                //console.log("账户输入框：", detectedFields.usernameField);
               // console.log("密码输入框：", detectedFields.passwordField);
                
                if (detectedFields.usernameField) {

                    detectedFields.usernameField.focus();
                    detectedFields.usernameField.value=json.Account;
                }

                if (detectedFields.passwordField) {
                    detectedFields.passwordField.focus();
                    detectedFields.passwordField.value=json.Password;
                }

            } else {
                //alert("未检测到登录输入框");
                chrome.runtime.sendMessage({type:'msg' ,data:"Login input box not detected"});
                showBadge("error","red");
            }
            break;
        default:
            break;
    }
});

function showBadge(text,color="#008000") {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color }); // 绿色背景
}
// 显示填充提示
function showPrompt() {

  const existsPrompt=document.querySelector(".fill-prompt");
  if (existsPrompt) {
    existsPrompt.remove();
  }

  const prompt = document.createElement('div');
  prompt.style.position = 'fixed';
  prompt.style.bottom = '20px';
  prompt.style.right = '20px';
  prompt.style.padding = '10px';
  prompt.style.backgroundColor = '#fff';
  prompt.style.border = '1px solid #ccc';
  prompt.style.borderRadius = '4px';
  prompt.style.boxShadow = '0 2px 10px rgba(0,0,0,0.1)';
  prompt.style.zIndex = '9999';
  prompt.className="fill-prompt";
  prompt.innerHTML = `
    <p>Login page detected</p>
    <button id="fill-credentials" style="background-color: green;color: white;">Request data ?</button>
  `;
  
  document.body.appendChild(prompt);
  
  // 绑定自动填充按钮点击事件
  document.getElementById('fill-credentials').addEventListener('click', () => {
     //登录页面 发消息 连接服务器
     chrome.runtime.sendMessage({type:'START_FETCH' ,tabid:0});
    prompt.remove();
  });
}

/**
 * 判断当前页面是否为登录页面（启发式规则）
 * @returns {boolean}
 */
function isLoginPage() {
    // 1. 检测是否存在密码输入框
    const passwordInputs = document.querySelectorAll("input[type='password']");
    if (passwordInputs.length > 0) {
      // 如果存在密码输入框，再做进一步判断
      // 如果表单中的输入字段不多，则更可能是登录页面
      const form = passwordInputs[0].closest("form");
      if (form) {
        const allInputs = form.querySelectorAll("input, select, textarea");
        // 登录表单一般字段数量较少（比如 2~4 个字段）
        if (allInputs.length <= 4) {
          return true;
        }
        // 或者检测表单中是否有用户名输入框
        // const usernameField = form.querySelector("input[type='text'], input[type='email']");
        // if (usernameField && /user|email/i.test(usernameField.name || usernameField.id || usernameField.placeholder)) {
        //   return true;
        // }

        let usernameCandidates = Array.from(form.querySelectorAll("input[type='text'], input[type='email']"));
      const candidateNames = [
        "username", "user", "login", "user_name", "user-name", "loginname", "login_name",
        "loginid", "login_id", "userid", "user_id", "userid", "useremail", "email", "emailaddress",
        "account", "acct", "identifier", "id", "用户名", "账号", "用户账号", "登陆名", "用户","name","ic","phone","phoneno"
      ];
      // 使用启发式规则筛选：检查 name、id、placeholder 属性中是否包含关键词
      let usernameField = usernameCandidates.find(input => {
        let attr = (input.name || input.id || input.placeholder || input.autocomplete || "").toLowerCase();
       const usernameFieldresult= candidateNames.some(candidate => attr.includes(candidate.toLowerCase()));

       if (usernameFieldresult) {
        return true;
       }
       // return /user|email|login|账号|name|username|account|/.test(attr);
      });
      }
      // 如果密码输入框比较孤立，也可以认为是登录页面
      return true;
    }
  
    // 2. 检测页面中是否存在专门用于登录的表单（无密码输入时）
    const forms = document.querySelectorAll("form");
    for (const form of forms) {
      // 尝试查找包含登录关键词的输入框或按钮
      const loginField = form.querySelector("input[name*='login'], input[id*='login'], input[placeholder*='login']");
      const passwordField = form.querySelector("input[type='password']");
      const submitBtn = form.querySelector("button, input[type='submit']");
      let btnText = "";
      if (submitBtn) {
        btnText = (submitBtn.textContent || submitBtn.value || "").toLowerCase();
      }
      if (loginField || /login|sign in|log in/i.test(btnText)) {
        // 如果没有密码框，但表单内有大量非登录输入字段（例如超过 4 个），则可能是数据录入页面
        const allInputs = form.querySelectorAll("input, select, textarea");
        if (allInputs.length > 4 && !passwordField) {
          continue;
        }
        return true;
      }
    }
  
    // 3. 检查 URL 或页面标题中是否含有登录相关关键词
    const url = window.location.href.toLowerCase();
    const title = document.title.toLowerCase();
    if (url.includes("login") || url.includes("signin") || title.includes("login") || title.includes("sign in")) {
      return true;
    }
    
    // 4. 其他特殊情况，可以根据需要扩展规则
    // 4. 检查 meta 标签中是否标识为登录的
    const metaPageType = document.querySelector("meta[name='page-type']");
    if (metaPageType && /login/i.test(metaPageType.content)) {
      return true;
    }

    // 如果以上条件都不满足，认为不是登录页面
    return false;
}

/**
 * 识别登录页面中的账户和密码输入框，支持无 `form` 和分步登录
 * @returns {Object|null} { usernameField, passwordField, container }
 */
function detectLoginFieldsWithoutForm() {
    const usernameKeywords =[
        "username", "user", "login", "user_name", "user-name", "loginname", "login_name",
        "loginid", "login_id", "userid", "user_id", "userid", "useremail", "email", "emailaddress",
        "account", "acct", "identifier", "id", "用户名", "账号", "用户账号", "登陆名", "用户","name","ic","phone","phoneno"
      ];

    function isUsernameField(input) {
        let attr = (input.name || input.id || input.placeholder || input.autocomplete || "").toLowerCase();
        //console.log(attr);
        const checkResult= usernameKeywords.some(keyword => attr.includes(keyword.toLowerCase()));
       // console.log("checkResult",checkResult);
        return checkResult;
    }

    // 获取所有输入框
    let textInputs = Array.from(document.querySelectorAll("input[type='text'], input[type='email']"));
    let passwordInputs = Array.from(document.querySelectorAll("input[type='password']"));

    //console.log(textInputs);
    //console.log(passwordInputs);

    // **情况 1**：正常登录（用户名+密码）
    if (passwordInputs.length > 0 && textInputs.length > 0) {
        for (let passwordField of passwordInputs) {
            let container = passwordField.closest("div, section, article") || document.body;
            let usernameCandidates = textInputs;//Array.from(container.querySelectorAll("input[type='text'], input[type='email']"));
            let usernameField = usernameCandidates.find(isUsernameField) || usernameCandidates[0];

            if (usernameField) {
                return { usernameField, passwordField, container };
            }
        }
    }

    // **情况 2**：第一步（只有用户名）
    if (passwordInputs.length === 0 && textInputs.length > 0) {
        let usernameField = textInputs.find(isUsernameField) || textInputs[0];
        return { usernameField, passwordField: null, container: usernameField.closest("div, section, article") || document.body };
    }

    // **情况 3**：第二步（只有密码框）
    if (passwordInputs.length > 0 && textInputs.length === 0) {
        let passwordField = passwordInputs[0];
        let container = passwordField.closest("div, section, article") || document.body;
        return { usernameField: null, passwordField, container };
    }

    return null;
}

function base64ToString(data) {
    return new TextDecoder().decode(Uint8Array.from(atob(data), c => c.charCodeAt(0)));
  }