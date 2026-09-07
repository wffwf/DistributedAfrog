# 分布式 Afrog 扫描系统

基于 Python 的分布式 afrog 漏洞扫描系统：

- **主控平台 (master)**：FastAPI 提供 Web UI 与 REST API，输入 URL、下发任务、呈现扫描结果。Web 界面**一比一复刻 afrog-web** 的展示效果（漏洞列表、Severity 配色、Request/Response 详情、分页等）。
- **工作节点 (worker)**：轮询 MongoDB 抢占任务，调用本地 afrog 二进制扫描，将结果回传 MongoDB。
- **Redis**：worker 心跳/在线状态监控（TTL 自动判定离线）。
- **MongoDB**：任务下发、任务状态、漏洞结果持久化。

## 架构

```
浏览器 ──► 主控 :8080 ──► MongoDB (任务下发/状态/结果)
                │
                └──► Redis (worker 心跳监控)
                              ▲
                              │ 心跳/拉任务
                              ▼
                       worker ──► afrog 扫描 ──► 结果写回 MongoDB
```

- 任务粒度 = 单个 URL。提交一批 URL 会生成一个 Scan（含 N 个 Task），worker 逐个抢占 URL 任务，天然支持多节点并发分流。
- worker 通过 `find_one_and_update(status: pending -> running)` 原子抢占，不会重复执行。

## 目录结构

```
.
├── docker-compose.yml         # 方案B: afrog容器桥接宿主机上 beholder 的 redis/mongo
├── docker-compose.merged.yml  # 方案A: 与 beholder 融合的一体化 compose(含 redis/mongo)
├── .env.example               # 环境变量模板(含 beholder mongo/redis 凭据)
├── master/                  # 主控(FastAPI)
│   ├── Dockerfile
│   └── app/
│       ├── main.py          # 应用入口
│       ├── config.py        # 配置
│       ├── db.py            # MongoDB(motor)
│       ├── redis_client.py  # Redis
│       ├── auth.py          # 登录会话
│       ├── models.py        # Pydantic 模型
│       ├── routers/
│       │   ├── api.py       # REST API
│       │   └── web.py       # 页面路由
│       ├── templates/       # login/results/tasks/new_task/workers
│       └── static/          # afrog-logo.svg
└── worker/                  # 工作节点
    ├── Dockerfile
    ├── worker.py            # 心跳+抢占+调用afrog+结果回传
    └── scripts/download_afrog.sh
```

## 快速开始

> 本系统**默认复用你已运行的 beholder 的 redis / mongo**，不另外启动中间件。

### 方案 A：把 master/worker 合并进 beholder 的 compose（推荐，同网络直连）

1. 复制 `.env.example` 为 `.env`，填好你的 beholder 凭据（`.env` 中已预填 `scan / YjHu1H9i0`，即你提供的默认值，如有差异请改动）。
2. 把 `docker-compose.merged.yml` 中除了 `redis`/`mongo` 之外的 `master`/`worker` 两块追加到 beholder 的 `docker-compose.yml`（它们会通过容器名 `beholder_redis` / `beholder_mongo` 同网络直连）。
3. 启动：
   ```bash
   cp .env.example .env
   docker compose up -d --build
   ```
4. 把 afrog 二进制放入 `afrog-bin/`，或 `docker compose exec worker download-afrog` 自动下载。

### 方案 B：beholder 在宿主机上跑，afrog 容器桥接访问（不动 beholder 文件）

`docker-compose.yml` 已配置为通过 `host.docker.internal` 访问宿主机上的 redis:6379 / mongo:27017（Linux 已加 `extra_hosts: host-gateway`）。

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec worker download-afrog   # 可选，自动下载 afrog 到 afrog-bin/
```

### 数据与凭据说明

- afrog 只使用 mongo 中**独立的 `afrog` 库**（`MONGO_DB=afrog`）和 redis 中 **`afrog:` 前缀**的 key，不会污染 beholder 自身数据。
- mongo 使用你的 root 账号 `scan` 连接（连接串带 `?authSource=admin`），redis 使用 requirepass。

### 使用

1. 浏览器打开 `http://localhost:8080`，登录。
2. **New Scan**：粘贴目标 URL（每行一个），可选 PoC 关键字(`-s`)、等级过滤(`-S`)与**代理**（HTTP/HTTPS/SOCKS5，支持多代理轮换，常用于经代理扫描内网目标），提交。
3. **Tasks**：查看各 Scan 进度（pending/running/done/failed、漏洞数）。
4. **Reports**：复刻 afrog-web 的漏洞列表 —— Severity 复选筛选、POC ID/名称搜索、点击表头展开漏洞详情与 Request/Response 对比、Copy 按钮、分页。
5. **Workers**：查看在线 worker、状态(idle/busy)、当前任务、心跳时间。

## REST API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/tasks` | 创建扫描任务 `{name, urls[], options{search,severity,proxy}}`（`proxy` 每行一个，支持 `http://` / `https://` / `socks5://`，多个则 afrog 自动轮换） |
| GET | `/api/tasks` | 扫描批次列表(含统计) |
| GET | `/api/tasks/{scan_id}` | 批次内子任务 |
| GET | `/api/results?severity=&keyword=&page=` | 漏洞结果(afrog-web 同款筛选) |
| GET | `/api/results/{id}` | 结果详情 |
| GET | `/api/workers` | worker 在线状态 |

## 分布式部署

master/worker 与 MongoDB/Redis 可部署在不同机器。只需在 `.env` 中把数据库地址改为远程 IP，无需修改 compose：

```ini
MONGO_HOST=10.0.0.5          # 远程 mongo 机器 IP
REDIS_HOST=10.0.0.6          # 远程 redis 机器 IP
```

也可直接用完整连接串 `MONGO_URI` / `REDIS_URL`（优先级更高）。各 worker 容器只需能访问到该数据库即可，天然支持跨机横向扩展。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MASTER_PASSWORD` | `change-me` | Web 登录密码 |
| `SECRET_KEY` | 内置默认值 | 会话签名密钥，生产必改 |
| `MONGO_URI` | 由拆分项拼接 | 完整 mongo 连接串(可选，优先级最高) |
| `MONGO_HOST` | `localhost` | MongoDB 主机/IP(远程部署改为远端 IP) |
| `MONGO_PORT` | `27017` | MongoDB 端口 |
| `MONGO_USER` / `MONGO_PASSWORD` | `scan` | mongo 账号 |
| `MONGO_AUTH_SOURCE` | `admin` | 认证库(root 账号一般为 admin) |
| `MONGO_DB` | `afrog` | afrog 独立使用的 mongo 库名 |
| `REDIS_URL` | 由拆分项拼接 | 完整 redis 连接串(可选，优先级最高) |
| `REDIS_HOST` | `localhost` | Redis 主机/IP(远程部署改为远端 IP) |
| `REDIS_PORT` | `6379` | Redis 端口 |
| `REDIS_PASSWORD` | 空 | redis requirepass |
| `REDIS_DB` | `2` | afrog 使用的 redis 库编号(避免与 beholder db0 冲突) |
| `WORKER_ID` | 自动生成 | worker 标识 |
| `AFROG_BIN` | `/app/afrog-bin/afrog` | afrog 二进制路径 |
| `AFROG_VERSION` | `latest` | 自动下载时用的版本 |
| `SCAN_TIMEOUT` | `1200` | 单目标扫描超时(秒) |
| `AFROG_EXTRA_ARGS` | `-nc` | 追加到 afrog 命令的额外参数 |
| `PUBLIC_IP_URLS` | `http://cip.cc,...` | 公网出口 IP 探测服务(逗号分隔，逐个尝试，默认含 cip.cc/ipinfo/ifconfig/ipify) |
| `PUBLIC_IP_REFRESH` | `600` | 公网 IP 刷新间隔(秒)，启动时立即获取一次并缓存 |

### 国内加速构建

默认已启用国内镜像源，无需额外配置：

- **pip**：走清华源（`PIP_INDEX_URL`，build-arg 可覆盖）
- **apt**：worker 走阿里源（`APT_MIRROR`，build-arg 可覆盖）
- **基础镜像拉取**（`python:3.11-slim`）：Docker Hub 在国内可能较慢，建议给 Docker daemon 配置 registry mirror（`/etc/docker/daemon.json` 的 `registry-mirrors`，如 `docker.1ms.run`），再 `docker compose build` 前先 `docker pull python:3.11-slim`

如需自定义镜像源：

```bash
docker compose build \
  --build-arg PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
  --build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn
```

## 说明

- 结果以 afrog `-json-all` 输出入库（含 request/response）。若希望减少存储，可把 worker 里的 `-json-all` 改为 `-json`。
- afrog 首次启动会自动更新 PoC 库，需 worker 容器能访问 GitHub；离线环境可提前把 pocs 目录与配置准备好。
- 免责声明：本工具仅用于已获授权的安全测试，请勿对未授权目标发起扫描。
