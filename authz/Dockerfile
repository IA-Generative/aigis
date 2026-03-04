FROM openpolicyagent/opa:latest-static AS opa

# ---- final image ----
FROM scratch

COPY --from=opa /opa /opa

# Policies
COPY policies/ /policies/
# Data initiale (vide — alimentée via API ou bundle)
COPY data/      /data/

EXPOSE 8181

ENTRYPOINT ["/opa"]
CMD [ "run", "--server", "--log-format=json", "--log-level=info", "--addr=0.0.0.0:8181", "--config-file=/policies/config.yaml", "/policies" ]