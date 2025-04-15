# WeTools.PassBox

整体思路：
1. app 作为 服务端，保存数据，推送数据，提供http服务
2. 插件 作为 客户端，只作为数据接收端并自动填充

通信逻辑：
1. app 开启http服务 并提示 当前服务地址
2. 用户 在pc 浏览器中，打开 服务地址 例如 https：//192.168.0.100：5885/getinfo
3. getinfo 加载后，content脚本 获取url中的ip地址， 发送到 background.js//使用 chrome.runtime.connect 让多个 Tab 共享数据
4. background.js 开启sse，等待app推送消息
5. background.js 接收到 推送消息，根据tabid，发生消息到content脚本，然后填充form或者文本框

技术点：
1. app 开启sse 服务
2. 在 Chrome 插件的 background.js 里，监听 MAUI Blazor 的 SSE 事件：

javascript

const eventSource = new EventSource("http://192.168.1.100:5000/events"); // MAUI 服务器 IP

eventSource.onmessage = (event) => {
    console.log("收到 MAUI 选中的数据：", event.data);

    // 发送到 Content Script
    chrome.runtime.sendMessage({ type: "dataUpdate", data: event.data });
};

eventSource.onerror = (error) => {
    console.error("SSE 连接失败", error);
};

