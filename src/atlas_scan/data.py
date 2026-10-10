"""Reference lists used by the supply-chain checks.

Popular package names are the targets attackers imitate. A dependency whose
name is one or two typos away from one of these is suspicious.
"""

POPULAR_PYPI = {
    "requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "flask", "django",
    "fastapi", "uvicorn", "gunicorn", "starlette", "pydantic", "sqlalchemy", "alembic", "psycopg2",
    "psycopg2-binary", "pymysql", "redis", "celery", "boto3", "botocore", "s3transfer", "awscli",
    "google-cloud-storage", "google-api-python-client", "openai", "anthropic", "langchain",
    "langchain-core", "langchain-community", "langchain-openai", "llama-index", "transformers",
    "tokenizers", "datasets", "huggingface-hub", "torch", "torchvision", "tensorflow", "keras",
    "scikit-learn", "xgboost", "lightgbm", "jax", "tiktoken", "sentence-transformers", "chromadb",
    "pinecone-client", "faiss-cpu", "httpx", "aiohttp", "beautifulsoup4", "lxml", "selenium",
    "playwright", "scrapy", "pillow", "opencv-python", "pyyaml", "toml", "tomli", "python-dotenv",
    "click", "typer", "rich", "tqdm", "colorama", "jinja2", "markupsafe", "werkzeug", "itsdangerous",
    "cryptography", "pycryptodome", "pyjwt", "bcrypt", "passlib", "paramiko", "certifi", "idna",
    "charset-normalizer", "six", "setuptools", "wheel", "pip", "virtualenv", "pytest", "pytest-cov",
    "coverage", "black", "ruff", "flake8", "mypy", "pylint", "isort", "pre-commit", "tox",
    "python-dateutil", "pytz", "arrow", "pendulum", "attrs", "dataclasses-json", "marshmallow",
    "protobuf", "grpcio", "websockets", "web3", "eth-account", "solana", "streamlit", "gradio",
    "jupyter", "notebook", "ipython", "pyarrow", "polars", "openpyxl", "xlrd", "docx", "python-docx",
    "pypdf", "pymupdf", "sympy", "networkx", "nltk", "spacy", "mcp", "tenacity", "loguru",
    "colorlog", "simplejson", "ujson", "orjson", "docker", "kubernetes", "ansible",
}

POPULAR_NPM = {
    "react", "react-dom", "next", "vue", "nuxt", "svelte", "@sveltejs/kit", "angular", "express",
    "koa", "fastify", "hono", "axios", "node-fetch", "got", "lodash", "underscore", "moment", "dayjs",
    "date-fns", "chalk", "commander", "yargs", "inquirer", "dotenv", "cross-env", "debug", "uuid",
    "nanoid", "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "cors", "helmet", "body-parser",
    "cookie-parser", "multer", "mongoose", "mongodb", "pg", "mysql", "mysql2", "sqlite3", "prisma",
    "@prisma/client", "sequelize", "typeorm", "drizzle-orm", "redis", "ioredis", "socket.io", "ws",
    "graphql", "apollo-server", "typescript", "ts-node", "tsx", "esbuild", "vite", "webpack",
    "rollup", "babel-loader", "@babel/core", "eslint", "prettier", "jest", "vitest", "mocha", "chai",
    "cypress", "playwright", "puppeteer", "tailwindcss", "postcss", "autoprefixer", "sass",
    "styled-components", "@emotion/react", "zod", "yup", "joi", "ajv", "rxjs", "redux",
    "@reduxjs/toolkit", "zustand", "jotai", "swr", "@tanstack/react-query", "react-router",
    "react-router-dom", "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "ai",
    "@modelcontextprotocol/sdk", "ethers", "viem", "web3", "wagmi", "@solana/web3.js", "hardhat",
    "@supabase/supabase-js", "firebase", "firebase-admin", "stripe", "aws-sdk", "@aws-sdk/client-s3",
    "nodemailer", "sharp", "cheerio", "jsdom", "marked", "highlight.js", "classnames", "clsx",
    "framer-motion", "three", "d3", "chart.js", "electron", "nodemon", "pm2", "concurrently",
    "rimraf", "glob", "fs-extra", "semver", "minimist", "colors", "request", "async", "bluebird",
    "core-js", "regenerator-runtime", "tslib", "@types/node", "@types/react",
}
