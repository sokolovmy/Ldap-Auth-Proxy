FROM python:3.9-alpine

COPY ldap-auth-proxy.py /opt/ldap-auth-proxy/

WORKDIR /opt/ldap-auth-proxy/

# Install required software
RUN \
    pip install ldap3 cachetools

EXPOSE 8080

CMD ["python", "/opt/ldap-auth-proxy/ldap-auth-proxy.py"]