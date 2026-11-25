# Paw

Paw 是一个自托管的 Windows 临时远程救援入口。管理员开启限时窗口并分享接入链接，目标用户在管理员 PowerShell 中执行一条命令，操作者或 agent 随后用标准 SSH 登录。窗口到期或手动关闭时，服务端会断开现有隧道，客户端会清理临时账号和任务。

服务端是一个 Go 进程，由单个容器运行。Windows x64 客户端会校验并缓存 OpenSSH 下载包。管理员可以在网页上配置 SSH SOCKS 下载代理，修改会在下次运行接入命令时生效。

## 运行

把管理员密码写到持久目录的 `admin-password` 文件。目录和文件需要允许容器用户 `65532` 读写。使用 HTTPS 反向代理将网页域名指向本机 `8080`，并发布两个 SSH TCP 端口。

```sh
docker run -d --name paw --restart unless-stopped \
  -e PAW_PUBLIC_URL=https://windows-support.example.com \
  -p 127.0.0.1:8080:8080 -p 49222:49222 -p 49223:49223 \
  -v /path/to/paw-data:/data \
  ghcr.io/neko-cwc/paw:latest
```

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `PAW_PUBLIC_URL` | `https://windows-support.284072.xyz` | 客户端和管理员访问的 HTTPS 入口 |
| `PAW_HTTP_ADDR` | `:8080` | HTTP 监听地址 |
| `PAW_RELAY_ADDR` | `:49222` | Windows 反向 SSH 中继监听地址 |
| `PAW_ACCESS_ADDR` | `:49223` | 操作者的 SSH 入口监听地址 |
| `PAW_SSH_HOST` | 网页域名 | 广告给客户端和操作者的 SSH 地址 |
| `PAW_RELAY_PORT` / `PAW_ACCESS_PORT` | 对应监听端口 | Docker 端口映射后的外部端口 |
| `PAW_DEFAULT_MINUTES` | `240` | 默认接入窗口时长 |
| `PAW_ADMIN_PASSWORD_FILE` | `/data/admin-password` | 管理员密码文件 |

网页提供两个公开共享文本框，每个最多 1 MB。接入窗口只在运行中的容器内有效。共享文本、代理配置和中继主机密钥保存在 `/data`。反向代理需允许 `/api/text/` 接收 1 MB 的请求体。

## 镜像

`ghcr.io/neko-cwc/paw:latest`
