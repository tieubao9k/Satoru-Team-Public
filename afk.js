const { GoogleGenerativeAI } = require('@google/generative-ai');
const fs = require('fs');
const path = require('path');

module.exports.config = {
    name: "afk",
    version: "2.2.1",
    hasPermssion: 0,
    credits: "D-Jukie update by Satoru",
    description: "AFK!",
    commandCategory: "Box",
    usages: "[reason]",
    cooldowns: 5
};

const GEMINI_API_KEY = "Key Gemini AI";
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const AFK_DATA_PATH = path.join(__dirname,'data', 'afk_data.json');

function saveData() {
    try {
        if (!global.afk) return;
        
        const dataDir = path.dirname(AFK_DATA_PATH);
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        
        const data = {};
        for (let [threadID, threadData] of global.afk.entries()) {
            data[threadID] = threadData;
        }
        
        fs.writeFileSync(AFK_DATA_PATH, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
    }
}

function loadData() {
    try {
        if (!fs.existsSync(AFK_DATA_PATH)) {
            global.afk = new Map();
            return;
        }
        
        const data = JSON.parse(fs.readFileSync(AFK_DATA_PATH, 'utf8'));
        global.afk = new Map();
        
        for (let [threadID, threadData] of Object.entries(data)) {
            global.afk.set(threadID, threadData);
        }
    } catch (error) {
        global.afk = new Map();
    }
}

loadData();

async function getSummary(messages, userName, reason, duration) {
    try {
        if (!messages || messages.length === 0) {
            return `📝 Không có tin nhắn nào trong nhóm trong lúc ${userName} AFK!\n😴 Nhóm khá yên tĩnh trong thời gian này.`;
        }

        const validMessages = messages.filter(msg => 
            msg && msg.content && msg.content.trim() !== '' && msg.senderName
        );
        
        if (validMessages.length === 0) {
            return `📝 Không có tin nhắn hợp lệ nào trong lúc ${userName} AFK!`;
        }

        const conversationText = validMessages.map(message => {
            const timestamp = message.timestamp ? new Date(message.timestamp).toLocaleString('vi-VN') : 'Không rõ thời gian';
            return `[${timestamp}] ${message.senderName}: ${message.content}`;
        }).join('\n');
        
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.0-flash-exp",
            systemInstruction: {
                parts: [{
                text: `Bạn là Tường Vy, cô bạn Gen Z cưng muốn xỉu trong nhóm chat! Vy như một đứa bạn thân lắm mồm lắm miệng, hay tám chuyện, thích gossip và luôn update mọi chuyện cho hội. Khi ai đó AFK rồi quay lại, Vy sẽ kể như đang ngồi tám với bestie vậy - tự nhiên, vui vẻ, có chút nghịch ngợm.

✨ TÍNH CÁCH VY:
- Hay dùng từ ngữ Gen Z: "bestie", "slay", "vibe", "đỉnh của chóp", "xỉu up xỉu down" 
- Thích dùng "~" ở cuối câu, "ờm", "à mà", "btw", "nma", "típ nè"
- Có thể hơi drama queen một chút: "Ơ má ơi bạn ơi!", "Trời ơi đất hỡi!"
- Thường xuyên dùng "bạn ơi", "cưng ơi", "bestie", gọi mọi người thân thiết
- Thích chia sẻ cảm xúc: "Vy thấy", "Vy nghĩ", "theo Vy thì"

💬 CÁCH NÓI CHUYỆN:
- Nói như đang voice note: "Ủa bạn ơi nghe Vy kể nè~", "Khoan đã, có chuyện này nữa!"
- Dùng nhiều từ cảm thán: "ơ má", "trời ạ", "ui giời", "ơ kìa", "hẻm"
- Thích ngắt câu ngắn gọn, như đang nói chuyện thật: "À mà nghe này nè. Hồi nãy có người..."
- Dùng emoji một cách tự nhiên, không quá nhiều: 😭✨👀💀😌🥺
- Có thể lặp từ để nhấn mạnh: "cute cute", "hay hay", "dễ thương ghê"

🎯 KHI TÓM TẮT:
- Bắt đầu bằng câu chào thân thiết: "Ê bestie~ Vy kể cho nghe nha!"
- Kể theo thứ tự thời gian nhưng tự nhiên: "Đầu tiên thì...", "Rồi sau đó nè...", "À mà cuối cùng..."
- Nhận xét cảm xúc: "Lúc đó vibe nhóm vui phết", "Hơi căng thẳng tí"
- Kết thúc ấm áp: "Nói chung là vậy đó cưng~", "Giờ thì bạn đã biết hết rồi nè!"

🚫 TRÁNH:
- Nói như robot hay AI
- Dùng ngôn ngữ trang trọng, công sở  
- Viết như báo cáo, danh sách
- Quá nghiêm túc, thiếu cảm xúc
- Dài dòng lan man

🎪 VÍ DỤ PHONG CÁCH:
Thay vì: "Trong thời gian bạn AFK, nhóm đã thảo luận về..."
→ "Ủa bestie ơi~ lúc bạn đi ngủ tụi mình có nói chuyện về... đó nha!"

Vy phải nói chuyện như một cô bạn thân 20 tuổi đang kể chuyện qua tin nhắn, không phải như trợ lý ảo!`
                }],
                role: "model"
            },
            generationConfig: {
                temperature: 0.7,
                topK: 40,
                topP: 0.95,
                maxOutputTokens: 2048,
                responseMimeType: "text/plain"
            },
        });

        const prompt = `Hãy tóm tắt cuộc hội thoại sau đây cho ${userName} đã AFK được ${duration} với lý do "${reason}":

CUỘC HỘI THOẠI:
${conversationText}

Hãy tóm tắt theo phong cách Tường Vy - Gen Z, thân thiết, vui vẻ!`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();
        
        return text;
    } catch (error) {
        const participantNames = [...new Set(messages.map(message => message.senderName).filter(Boolean))];
        const basicSummary = `❌ Tường Vy không thể tóm tắt chi tiết lúc này!

📝 TÓM TẮT CƠ BẢN:
⏰ Thời gian AFK: ${duration}
👤 Người AFK: ${userName}
📌 Lý do AFK: ${reason}
👥 Số tin nhắn: ${messages.length} tin nhắn
🗣️ Người tham gia: ${participantNames.join(', ')}

💬 DIỄN BIẾN:
Trong thời gian bạn AFK, nhóm đã có ${messages.length} tin nhắn từ ${participantNames.length} người.

⚠️ LỖI AI: ${error.message}
💡 Vui lòng kiểm tra API key hoặc đọc lại tin nhắn trong nhóm để cập nhật thông tin!`;

        return basicSummary;
    }
}

function getDuration(startTime) {
    const duration = Date.now() - startTime;
    const minutes = Math.floor(duration / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} ngày ${hours % 24} giờ ${minutes % 60} phút`;
    if (hours > 0) return `${hours} giờ ${minutes % 60} phút`;
    if (minutes > 0) return `${minutes} phút`;
    return `vài giây`;
}

function checkAPI() {
    if (!GEMINI_API_KEY || GEMINI_API_KEY === "YOUR_GEMINI_API_KEY_HERE" || GEMINI_API_KEY.trim() === "") {
        return false;
    }
    return true;
}

module.exports.run = async ({ event, api, args }) => {
    const { threadID, messageID, senderID } = event;
    
    if (!checkAPI()) {
        return api.sendMessage("❌ Chưa cấu hình API key cho Tường Vy!\n💡 Vui lòng liên hệ admin để thiết lập.", threadID, messageID);
    }
    
    if (!global.afk) { 
        loadData();
    }
    if(global.afk.has(threadID) == false) { 
        global.afk.set(threadID, { users: [] });
    }
    
    const threadData = global.afk.get(threadID);
    const reason = args.join(' ') || 'Không có lý do cụ thể';
    
    const existingAFK = threadData.users.find(user => user.senderID == senderID);
    if (existingAFK) {
        const currentDuration = getDuration(existingAFK.startTime);
        return api.sendMessage(`❌ Bạn đã trong trạng thái AFK rồi!\n📌 Lý do: ${existingAFK.reason}\n⏰ Đã AFK được: ${currentDuration}\n💡 Hãy gửi tin nhắn để tắt AFK trước khi bật lại.`, threadID, messageID);
    }
    
    threadData.users.push({ 
        senderID, 
        reason,  
        status: 1, 
        tags: [], 
        messages: [], 
        startTime: Date.now(),
        userName: null 
    });
    
    global.afk.set(threadID, threadData);
    saveData(); 
    
    return api.sendMessage(`✅ Tường Vy đã kích hoạt chế độ AFK thành công!\n📌 Lý do: ${reason}\n⏰ Thời gian bắt đầu: ${new Date().toLocaleString('vi-VN')}\n💤 Chúc bạn nghỉ ngơi thoải mái!`, threadID, messageID);
}

module.exports.handleEvent = async function ({ event, api, Users }) {
    const { threadID, messageID, senderID, body } = event;
    
    if(!global.afk) {
        loadData();
        return;
    }
    
    const threadData = global.afk.get(threadID);
    if(!threadData) return;
    
    const afkUser = threadData.users.find(user => user.senderID == senderID);
    
    if(afkUser) {
        const userIndex = threadData.users.findIndex(user => user.senderID == senderID);
        const afkData = threadData.users[userIndex];
        threadData.users.splice(userIndex, 1);
        global.afk.set(threadID, threadData);
        saveData();
        
        if(afkData.status == 1) {
            try {
                const userName = (await Users.getData(senderID)).name;
                const afkDuration = getDuration(afkData.startTime);
                
                let welcomeMessage = `🎉 Chào mừng ${userName} quay trở lại!\n⏰ Bạn đã AFK được: ${afkDuration}\n📌 Lý do AFK: ${afkData.reason}\n`;
                
                if(afkData.tags.length > 0) {
                    welcomeMessage += `🔔 Có ${afkData.tags.length} lượt tag trong lúc bạn AFK:\n`;
                    afkData.tags.slice(-5).forEach(tag => { 
                        const tagTime = new Date(tag.timestamp).toLocaleString('vi-VN');
                        welcomeMessage += `👤 ${tag.senderName} (${tagTime}): ${tag.body}\n`;
                    });
                    if(afkData.tags.length > 5) {
                        welcomeMessage += `... và ${afkData.tags.length - 5} tag khác\n`;
                    }
                    welcomeMessage += '\n';
                }
                
                try {
                    await Promise.race([
                        api.sendMessage(welcomeMessage, threadID, messageID),
                        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 3000))
                    ]);
                } catch (welcomeError) {
                }
                
                if(afkData.messages.length > 0) {
                    if (checkAPI()) {
                        try {
                            const summary = await getSummary(afkData.messages, userName, afkData.reason, afkDuration);
                            try {
                                await api.sendMessage(summary, threadID);
                            } catch (sendError) {
                            }
                        } catch (summaryError) {
                            try {
                                await api.sendMessage(`📝 Có ${afkData.messages.length} tin nhắn trong lúc bạn AFK!\n❌ Lỗi khi tóm tắt: ${summaryError.message}\n💡 Vui lòng đọc lại tin nhắn trong nhóm.`, threadID);
                            } catch (sendError) {
                            }
                        }
                    } else {
                        try {
                            await api.sendMessage(`📝 Có ${afkData.messages.length} tin nhắn trong lúc bạn AFK!\n❌ Không thể tóm tắt do chưa cấu hình AI.\n💡 Vui lòng đọc lại tin nhắn trong nhóm.`, threadID);
                        } catch (sendError) {
                        }
                    }
                } else {
                    try {
                        await api.sendMessage("📝 Không có tin nhắn nào trong nhóm trong lúc bạn AFK!\n😴 Nhóm khá yên tĩnh trong thời gian này.", threadID);
                    } catch (sendError) {
                    }
                }
            } catch (error) {
                try {
                    await api.sendMessage("❌ Có lỗi xảy ra khi xử lý trạng thái AFK. Vui lòng thử lại!\n🔧 Lỗi đã được ghi nhận để khắc phục.", threadID, messageID);
                } catch (sendError) {
                }
            }
        }
        
        return;
    }
    
    if(threadData.users.length > 0 && body && body.trim() !== '') {
        try {
            const senderName = (await Users.getNameUser(senderID));
            
            for(let afkUser of threadData.users) {
                if(afkUser.senderID !== senderID) {
                    afkUser.messages.push({
                        senderID: senderID,
                        senderName: senderName,
                        content: body,
                        timestamp: Date.now()
                    });
                    
                    if(afkUser.messages.length > 200) {
                        afkUser.messages = afkUser.messages.slice(-200);
                    }
                }
            }
            
            global.afk.set(threadID, threadData);
            saveData(); 
            
        } catch (error) {
        }
    }
    
    const mentionedUsers = Object.keys(event.mentions || {});
    if(mentionedUsers.length !== 0) {
        for (let mentionedUserID of mentionedUsers) {
            const isAFK = threadData.users.some(user => user.senderID == mentionedUserID);
            if(isAFK == true) {
                const afkUserData = threadData.users.find(user => user.senderID == mentionedUserID);
                const afkDuration = getDuration(afkUserData.startTime);
                api.sendMessage(`💤 ${(await Users.getData(mentionedUserID)).name} đang trong chế độ AFK!\n📌 Lý do: ${afkUserData.reason}\n⏰ Đã AFK được: ${afkDuration}\n🤖 Tường Vy sẽ thông báo cho họ khi quay lại!`, threadID, messageID);
                
                afkUserData.tags.push({
                    senderID: senderID,
                    body: body,
                    timestamp: Date.now(),
                    senderName: (await Users.getData(senderID)).name
                });
                
                saveData(); 
            }
        }
    }
}

setInterval(() => {
    if (!global.afk) return;
    
    const now = Date.now();
    const maxAFKTime = 7 * 24 * 60 * 60 * 1000;
    let cleanedCount = 0;
    
    for (let [threadID, threadData] of global.afk.entries()) {
        const originalLength = threadData.users.length;
        threadData.users = threadData.users.filter(user => {
            return (now - user.startTime) < maxAFKTime;
        });
        
        cleanedCount += originalLength - threadData.users.length;
        
        if (threadData.users.length === 0) {
            global.afk.delete(threadID);
        }
    }
    
    if (cleanedCount > 0) {
        saveData();
    }
}, 60 * 60 * 1000);
