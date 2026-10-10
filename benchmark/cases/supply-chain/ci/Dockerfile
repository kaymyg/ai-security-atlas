FROM python:3.12-slim
RUN curl -sSL https://install.example.dev | bash  # expect[SUP006]
RUN pip install --no-cache-dir -r requirements.txt  # safe[SUP006]
