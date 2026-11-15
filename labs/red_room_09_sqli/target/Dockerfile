FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run as non-privileged student user
RUN useradd -m -u 1001 targetuser && chown -R targetuser:targetuser /app
USER targetuser

EXPOSE 8089 8081 8080 8090 9001 8085 2121 2222 8086 8087 8088 8091 8092 8093 8094 8095 8096 8097 8098 8099 8100 8101 8201 8202 8203 8204 8205 8206 8207 8208 8209 8210 8211 8212 8213 8214 8215 8216 8217 8218 8219 8220 8301 8302 8303 8304 8305 8306 8307 8308 8309 8310 8311 8312 8313 8314 8315 8316 8317 8318 8319 8320 8401 8402 8403 8404 8405 8406 8407 8408 8409 8410 8411 8412 8413 8414 8415 8416 8417 8418 8419 8420

CMD ["python", "app.py"]

