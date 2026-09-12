# ZENITH Production Deployment Guide: Vercel & Render

A step-by-step guide for deploying **ZENITH — Attack Path & Identity Privilege Graph Analyzer** into production:
- **Frontend (UI & Landing Page)**: Hosted on **Vercel** with edge routing, instant CDN delivery, and automatic landing page redirection.
- **Backend (API & Intelligence)**: Hosted on **Render** (Node.js/Express Web Service) connected to **Neo4j Aura** cloud and **NVIDIA NIM**.

---

## 1. Architecture Overview

```
+-------------------------------------------------------------------------+
|                                 USER BROWSER                            |
+-------------------------------------------------------------------------+
       |                                              |
       | 1. HTTP / Landing / UI                       | 2. API / Queries
       v                                              v
+-------------------------------+             +---------------------------+
|        VERCEL (Frontend)      |             |      RENDER (Backend)     |
| - Landing Page (/landing-page)|             | - Express / Node.js 20    |
| - React SPA Console (?console)|             | - Dijkstra Shortest Path  |
| - vercel.json Edge Rewrites   |             | - Blast Radius Engine     |
+-------------------------------+             | - Scenario Injection API  |
                                              +---------------------------+
                                                            |
                                             +--------------+--------------+
                                             |                             |
                                             v                             v
                                  +--------------------+        +--------------------+
                                  |     Neo4j Aura     |        |     NVIDIA NIM     |
                                  | Cloud Graph DB     |        | Live AI Reasoning  |
                                  | 129+88 Dual Set    |        | Llama 3.1 / DeepS. |
                                  +--------------------+        +--------------------+
```

---

## 2. Deploy Backend on Render

### Method A: One-Click Blueprint Deployment (Recommended)

1. Log in to your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** in the top-right corner and select **Blueprint**.
3. Connect your GitHub repository:
   - `Conqueror17-AALOK/KH050-MetaWiz-ZENITH` or `Conqueror17-AALOK/ZENITH-`.
4. Render will automatically detect [render.yaml](render.yaml) in the repository root.
5. Under **Environment Variables**, fill in your secret credentials:
   - `NEO4J_URI`: `neo4j+s://a8a3cb97.databases.neo4j.io`
   - `NEO4J_USER` / `NEO4J_USERNAME`: `a8a3cb97`
   - `NEO4J_PASSWORD`: `scLTv7IBSMWoCNluP9mE5W-46anF8BHBytBWg45ObPs`
   - `NEO4J_DATABASE`: `a8a3cb97`
   - `NVIDIA_API_KEY`: `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`
   - `NVIDIA_MODEL`: `meta/llama-3.1-70b-instruct`
6. Click **Apply**. Render will build and deploy the backend service.

---

### Method B: Manual Web Service Setup

If you prefer to configure the Web Service manually:
1. In Render Dashboard, click **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Configure the following service settings:
   - **Name**: `zenith-backend`
   - **Language / Runtime**: `Node`
   - **Root Directory**: `src/backend`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Health Check Path**: `/health`
4. Scroll down to **Environment Variables** and add:
   | Key | Value | Notes |
   | :--- | :--- | :--- |
   | `PORT` | `10000` | Auto-routed by Render |
   | `NODE_VERSION` | `20` | Node LTS |
   | `CORS_ORIGIN` | `*` | Or your Vercel URL (`https://*.vercel.app`) |
   | `NEO4J_URI` | `neo4j+s://a8a3cb97.databases.neo4j.io` | Neo4j Aura endpoint |
   | `NEO4J_USER` | `a8a3cb97` | Database username |
   | `NEO4J_PASSWORD` | `scLTv7IBSMWoCNluP9mE5W-46anF8BHBytBWg45ObPs` | Database password |
   | `NEO4J_DATABASE` | `a8a3cb97` | Database name |
   | `NVIDIA_API_KEY` | `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` | AI reasoning layer |
   | `NVIDIA_MODEL` | `meta/llama-3.1-70b-instruct` | AI model |
5. Click **Create Web Service**.
6. Once deployed, copy your Render service URL (e.g. `https://zenith-backend.onrender.com`).
7. Test the health check endpoint in your browser:
   ```bash
   curl https://<your-render-service>.onrender.com/health
   # Expected response: {"status":"ok","service":"zenith-backend",...}
   ```

---

## 3. Deploy Frontend on Vercel

1. Log in to your [Vercel Dashboard](https://vercel.com/).
2. Click **Add New...** -> **Project**.
3. Import your GitHub repository (`Conqueror17-AALOK/KH050-MetaWiz-ZENITH` or `Conqueror17-AALOK/ZENITH-`).
4. In the **Configure Project** screen:
   - **Project Name**: `zenith-analyzer` (or any name)
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click **Edit** and choose `src/frontend` (or leave as root `./` since root `vercel.json` is configured).
   - **Build Command**: `npm run build` (or `vite build`)
   - **Output Directory**: `dist`
5. Expand **Environment Variables**:
   - Add `VITE_API_URL` with the URL of your deployed Render backend:
     - **Name**: `VITE_API_URL`
     - **Value**: `https://<your-render-service>.onrender.com` (e.g., `https://zenith-backend.onrender.com`)
6. Click **Deploy**.
7. Vercel will build and deploy the application in ~30 seconds.

---

## 4. Post-Deployment Verification Checklist

- [ ] **Landing Page Initial Route**:
  - Visit `https://<your-app>.vercel.app/`.
  - It should automatically load the dark luxury Landing Page at `/landing-page/index.html`.
- [ ] **Console Launch**:
  - Click **Launch Console** (or visit `https://<your-app>.vercel.app/?console=true`).
  - The Graph Console should load seamlessly with:
    - **DEMO BENCHMARK GRAPH** (129 nodes, 200 edges).
    - Planted attack path highlighted in red.
- [ ] **Dataset Isolation**:
  - Click **IMPORT ADSYNTH DATA**:
    - Switches immediately to **ADSYNTH DATASET GRAPH** (88 nodes, 123 edges).
    - Scenario presets update to ADSynth scenarios.
  - Click **DEMO GRAPH MODE**:
    - Switches immediately back to Demo Benchmark graph.
- [ ] **Live AI Reasoning**:
  - Click **Generate Autonomous Threat Briefing**.
  - Verified live NVIDIA NIM response streaming or fallback risk analysis.
