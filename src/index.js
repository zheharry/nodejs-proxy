// 首先建立 package.json，加入 "type": "module"
// {
//   "name": "vpn-server",
//   "version": "1.0.0",
//   "type": "module",
//   "main": "server.js"
// }

import tls from 'tls';
import net from 'net';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// 獲取當前文件路徑
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// TLS 配置
const tlsOptions = {
  key: readFileSync(join(__dirname, 'server-key.pem')),
  cert: readFileSync(join(__dirname, 'server-cert.pem')),
  ciphers: 'AES256-GCM-SHA384:AES128-GCM-SHA256',
  minVersion: 'TLSv1.3'
};

// VPN 配置 
const vpnConfig = {
  port: 80,
  subnet: '10.8.0.0',
  netmask: '255.255.255.0'
};

// 客戶端連接池
const clients = new Map();

// 創建 VPN server
const server = tls.createServer(tlsOptions, (client) => {
  console.log('Client connected');
  
  // 分配虛擬 IP
  const clientIP = assignIP();
  clients.set(client, {
    ip: clientIP,
    active: true
  });

  // 處理加密數據
  client.on('data', (data) => {
    const decrypted = decrypt(data);
    routePacket(decrypted, client);
  });

  client.on('close', () => {
    clients.delete(client);
    console.log('Client disconnected');
  });
});

// 分配 IP 地址
function assignIP() {
  const subnet = vpnConfig.subnet.split('.');
  const lastOctet = clients.size + 1;
  return `${subnet[0]}.${subnet[1]}.${subnet[2]}.${lastOctet}`;
}

// 數據包路由
function routePacket(packet, sourceClient) {
  const destinationIP = extractDestinationIP(packet);
  
  for (const [client, info] of clients.entries()) {
    if (client !== sourceClient && info.ip === destinationIP) {
      const encrypted = encrypt(packet);
      client.write(encrypted);
      break;
    }
  }
}

// 加密函數
function encrypt(data) {
  const cipher = crypto.createCipheriv('aes-256-gcm', 
    crypto.randomBytes(32),
    crypto.randomBytes(12)
  );
  return Buffer.concat([
    cipher.update(data),
    cipher.final(),
    cipher.getAuthTag()
  ]);
}

// 解密函數
function decrypt(data) {
  const decipher = crypto.createDecipheriv('aes-256-gcm',
    crypto.randomBytes(32),
    crypto.randomBytes(12)
  );
  decipher.setAuthTag(data.slice(data.length - 16));
  return Buffer.concat([
    decipher.update(data.slice(0, -16)),
    decipher.final()
  ]);
}

// 啟動服務器
server.listen(vpnConfig.port, () => {
  console.log(`VPN server listening on port ${vpnConfig.port}`);
});
