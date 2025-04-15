

const msgDiv=document.getElementById("msg");
const fillBtn=document.getElementById("fill-password");

fillBtn.addEventListener("click",async()=>{
  try {
    
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      const currentTab = tabs[0];
      console.log(currentTab);
      chrome.runtime.sendMessage({type:'START_FETCH' ,tabid:currentTab.id});
    });
    
  } catch (error) {
    console.log(error);
    updateMsg(error);
  }
});

function updateMsg(msg) {
  msgDiv.textContent=msg;
}

chrome.runtime.sendMessage({type:"GET_ERROR"},(response) => {
  if (response.status==0) {
    updateMsg(response.data);
  }
});

// chrome.runtime.onMessage.addEventListener((message, sender, sendResponse) => {
//   if (message.type==="msg") {
//     updateMsg(message.data);
//   }
// });