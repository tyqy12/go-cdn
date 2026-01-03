#!/usr/bin/env python3
"""
AI CDN Tunnel - 客户端使用示例
支持 QUIC、WebSocket、HTTP 多种协议
"""

import asyncio
import aiohttp
import json
import time
from typing import AsyncIterator, Optional

class ACDNClient:
    """AI CDN Tunnel 客户端"""
    
    def __init__(
        self,
        base_url: str = "https://ai-cdn.local",
        api_key: str = None,
        timeout: float = 30.0,
        max_concurrent: int = 100
    ):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        
        # 连接池
        self.connector = aiohttp.TCPConnector(
            limit=max_concurrent,
            limit_per_host=20,
            ttl_dns_cache=300,
            keepalive_timeout=30
        )
        
        # 请求头
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream"
        }
        if api_key:
            self.headers["X-API-Key"] = api_key
    
    async def close(self):
        """关闭连接池"""
        await self.connector.close()
    
    async def chat(self, message: str, stream: bool = True) -> dict:
        """
        发送对话请求
        
        Args:
            message: 用户消息
            stream: 是否使用流式响应
            
        Returns:
            响应结果
        """
        async with aiohttp.ClientSession(
            connector=self.connector,
            headers=self.headers,
            timeout=self.timeout
        ) as session:
            async with session.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": "llm-model",
                    "messages": [{"role": "user", "content": message}],
                    "stream": stream
                }
            ) as response:
                if response.status != 200:
                    error = await response.text()
                    raise Exception(f"请求失败: {response.status} - {error}")
                
                if stream:
                    return await self._handle_stream(response)
                else:
                    return await response.json()
    
    async def _handle_stream(self, response) -> AsyncIterator[str]:
        """
        处理SSE流式响应
        
        Yields:
            流式数据块
        """
        async for line in response.content:
            line = line.decode('utf-8').strip()
            if line.startswith('data: '):
                data = line[6:]
                if data == '[DONE]':
                    break
                try:
                    chunk = json.loads(data)
                    if 'choices' in chunk:
                        delta = chunk['choices'][0].get('delta', {})
                        content = delta.get('content', '')
                        if content:
                            yield content
                except json.JSONDecodeError:
                    pass
    
    async def chat_stream(self, message: str) -> AsyncIterator[str]:
        """
        便捷的流式对话方法
        
        Example:
            async for token in client.chat_stream("你好"):
                print(token, end="", flush=True)
        """
        async for token in self.chat(message, stream=True):
            yield token
    
    async def chat_complete(self, message: str) -> str:
        """
        非流式对话，获取完整响应
        
        Returns:
            完整的对话响应
        """
        result = await self.chat(message, stream=False)
        return result['choices'][0]['message']['content']


class H3Client:
    """QUIC (HTTP/3) 专用客户端"""
    
    def __init__(
        self,
        url: str = "https://ai-cdn.local",
        api_key: str = None
    ):
        # 注意: 需要安装支持HTTP/3的库
        # pip install aioquic
        try:
            from aioquic.asyncio connect
            self.quic_available = True
        except ImportError:
            self.quic_available = False
            print("警告: aioquic未安装，将回退到HTTP/2")
        
        self.url = url
        self.api_key = api_key
    
    async def chat(self, message: str, stream: bool = True) -> dict:
        """发送QUIC请求"""
        # QUIC实现需要aioquic库
        # 这里提供接口，实际实现请参考aioquic文档
        raise NotImplementedError("QUIC客户端需要aioquic库支持")


class WebSocketClient:
    """WebSocket 客户端"""
    
    def __init__(
        self,
        url: str = "wss://ai-cdn.local/ws",
        api_key: str = None
    ):
        self.url = url
        self.api_key = api_key
        self.ws = None
    
    async def connect(self):
        """建立WebSocket连接"""
        import aiohttp
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        
        async with aiohttp.ClientSession() as session:
            self.ws = await session.ws_connect(
                self.url,
                headers=headers,
                protocols=["graphql-ws"]
            )
        return self.ws
    
    async def send(self, message: dict):
        """发送消息"""
        if self.ws:
            await self.ws.send_json(message)
    
    async def receive(self) -> dict:
        """接收消息"""
        if self.ws:
            return await self.ws.receive_json()
    
    async def close(self):
        """关闭连接"""
        if self.ws:
            await self.ws.close()


# 使用示例
async def main():
    # 创建客户端
    client = ACDNClient(
        base_url="https://ai-cdn.local",
        api_key="sk-xxxxx"
    )
    
    try:
        # 非流式对话
        print("=== 非流式对话 ===")
        response = await client.chat_complete("请介绍一下你自己")
        print(f"响应: {response}\n")
        
        # 流式对话
        print("=== 流式对话 ===")
        print("响应: ", end="", flush=True)
        async for token in client.chat_stream("请讲一个笑话"):
            print(token, end="", flush=True)
        print("\n")
        
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
