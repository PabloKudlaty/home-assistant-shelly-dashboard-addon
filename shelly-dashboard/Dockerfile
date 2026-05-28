ARG BUILD_FROM
FROM ${BUILD_FROM}
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt
COPY shelly_dashboard_firmware.py /app/shelly_dashboard_firmware.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh
CMD [ "/run.sh" ]
