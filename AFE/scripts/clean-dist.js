import { readdir, unlink, rm } from 'fs/promises';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const distDir = join(__dirname, '..', 'dist');

async function cleanDist() {
  try {
    const entries = await readdir(distDir, { withFileTypes: true });
    
    for (const entry of entries) {
      // 跳过 .user.ini 文件
      if (entry.name === '.user.ini') {
        continue;
      }
      
      const fullPath = join(distDir, entry.name);
      
      if (entry.isDirectory()) {
        await rm(fullPath, { recursive: true, force: true });
      } else if (entry.isFile()) {
        await unlink(fullPath);
      }
    }
    
    console.log(' dist directory cleaned (preserving .user.ini)');
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.log(' dist directory does not exist, skipping clean');
    } else {
      console.error('Error cleaning dist:', error);
      process.exit(1);
    }
  }
}

// 使用 IIFE 包装 async 函数，确保 Promise 被正确处理
(async () => {
  try {
    await cleanDist();
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  }
})();
