require("dotenv").config();
const express = require("express");
const axios = require("axios");
const { parseStringPromise } = require("xml2js");
const WXBizMsgCrypt = require("./wxcrypto");

const app = express();
app.use(express.text({ type: "text/xml" }));
app.use(express.text({ type: "application/xml" }));
app.use(express.raw({ type: "*/*", limit: "1mb" }));

const {
  WX_CORP_ID,
  WX_AGENT_ID,
  WX_SECRET,
  WX_TOKEN,
  WX_ENCODING_AES_KEY,
  COZE_API_TOKEN,
  COZE_BOT_ID,
  PORT = 3000,
} = process.env;

const wxCrypt = new WXBizMsgCrypt(WX_TOKEN, WX_ENCODING_AES_KEY, WX_CORP_ID);

let wxAccessToken = "";
let tokenExpireAt = 0;

async function getWxAccessToken() {
  if (wxAccessToken && Date.now() < tokenExpireAt) return wxAccessToken;
  const res = await axios.get("https://qyapi.weixin.qq.com/cgi-bin/gettoken", {
    params: { corpid: WX_CORP_ID, corpsecret: WX_SECRET },
  });
  if (res.data.errcode !== 0) throw new Error(`WeChat token error: ${res.data.errmsg}`);
  wxAccessToken = res.data.access_token;
  tokenExpireAt = Date.now() + (res.data.expires_in - 300) * 1000;
  return wxAccessToken;
}

async function sendWxMessage(userId, content) {
  const token = await getWxAccessToken();
  await axios.post(
    `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${token}`,
    {
      touser: userId,
      msgtype: "text",
      agentid: parseInt(WX_AGENT_ID),
      text: { content },
    }
  );
}

async function chatWithCoze(message, userId) {
  const res = await axios.post(
    "https://api.coze.com/v3/chat",
    {
      bot_id: COZE_BOT_ID,
      user_id: `wx_${userId}`,
      stream: false,
      auto_save_history: true,
      additional_messages: [{ role: "user", content: message, content_type: "text" }],
    },
    {
      headers: {
        Authorization: `Bearer ${COZE_API_TOKEN}`,
        "Content-Type": "application/json",
      },
    }
  );

  const chatId = res.data.data.id;
  const conversationId = res.data.data.conversation_id;

  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    const status = await axios.get(
      `https://api.coze.com/v3/chat/retrieve?chat_id=${chatId}&conversation_id=${conversationId}`,
      { headers: { Authorization: `Bearer ${COZE_API_TOKEN}` } }
    );
    if (status.data.data.status === "completed") {
      const msgs = await axios.get(
        `https://api.coze.com/v3/chat/message/list?chat_id=${chatId}&conversation_id=${conversationId}`,
        { headers: { Authorization: `Bearer ${COZE_API_TOKEN}` } }
      );
      const answer = msgs.data.data.find((m) => m.type === "answer");
      return answer ? answer.content : "抱歉，我暂时无法回答这个问题。";
    }
    if (status.data.data.status === "failed") {
      return "抱歉，系统繁忙，请稍后再试。";
    }
  }
  return "抱歉，回复超时，请稍后再试。";
}

// Enterprise WeChat URL verification
app.get("/callback", (req, res) => {
  try {
    const { msg_signature, timestamp, nonce, echostr } = req.query;
    const reply = wxCrypt.verifyURL(msg_signature, timestamp, nonce, echostr);
    console.log("[OK] URL verification passed");
    res.send(reply);
  } catch (e) {
    console.error("[ERR] URL verification failed:", e.message);
    res.status(403).send("Verification failed");
  }
});

// Receive messages from Enterprise WeChat
app.post("/callback", async (req, res) => {
  res.send("success");

  try {
    const { msg_signature, timestamp, nonce } = req.query;
    const body = typeof req.body === "string" ? req.body : req.body.toString("utf8");
    const xml = await parseStringPromise(body);
    const encrypted = xml.xml.Encrypt[0];

    const decrypted = wxCrypt.decryptMsg(msg_signature, timestamp, nonce, encrypted);
    const msgXml = await parseStringPromise(decrypted);

    const msgType = msgXml.xml.MsgType[0];
    const fromUser = msgXml.xml.FromUserName[0];

    if (msgType !== "text") {
      await sendWxMessage(fromUser, "收到您发送的内容。请用文字描述一下您的需求，我可以更准确地帮您处理。");
      return;
    }

    const content = msgXml.xml.Content[0];
    console.log(`[MSG] ${fromUser}: ${content}`);

    const reply = await chatWithCoze(content, fromUser);
    console.log(`[BOT] → ${fromUser}: ${reply.slice(0, 80)}...`);
    await sendWxMessage(fromUser, reply);
  } catch (e) {
    console.error("[ERR] Message processing failed:", e.message);
  }
});

app.get("/health", (req, res) => res.json({ status: "ok", bot_id: COZE_BOT_ID }));

app.listen(PORT, () => {
  console.log(`Open Media Bot bridge running on port ${PORT}`);
  console.log(`Callback URL: /callback`);
});
