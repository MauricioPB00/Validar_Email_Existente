from fastapi import FastAPI
from pydantic import BaseModel, EmailStr
import dns.resolver
import smtplib
import socket

app = FastAPI(title="Validador de E-mails")


class EmailRequest(BaseModel):
    email: EmailStr


@app.get("/")
def home():
    return {"status": "online"}


@app.post("/validar-email")
def validar_email(dados: EmailRequest):
    email = str(dados.email).strip()
    dominio = email.rsplit("@", 1)[1]

    try:
        mx_records = dns.resolver.resolve(dominio, "MX", lifetime=5)
        servidores = sorted(mx_records, key=lambda r: r.preference)

    except Exception:
        return {
            "email": email,
            "valido": False,
            "status": "invalido",
            "mensagem": "Domínio sem MX acessível.",
        }

    for registro in servidores:
        servidor = str(registro.exchange).rstrip(".")

        try:
            with smtplib.SMTP(servidor, 25, timeout=8) as smtp:
                smtp.ehlo("verify.example.com")

                codigo, _ = smtp.mail("")
                if codigo >= 400:
                    continue

                codigo, resposta = smtp.rcpt(email)
                texto = resposta.decode("utf-8", errors="ignore").lower()

                if codigo in (250, 251):
                    return {
                        "email": email,
                        "valido": True,
                        "status": "aceito_pelo_servidor",
                        "mensagem": (
                            "O servidor aceitou o destinatário, "
                            "mas isso não garante que a caixa exista."
                        ),
                    }

                if codigo == 550 and (
                    "5.1.1" in texto
                    or "user unknown" in texto
                    or "mailbox not found" in texto
                ):
                    return {
                        "email": email,
                        "valido": False,
                        "status": "invalido",
                        "mensagem": (
                            "O servidor indicou que o destinatário " "não existe."
                        ),
                    }

        except (
            smtplib.SMTPException,
            socket.timeout,
            OSError,
        ):
            continue

    return {
        "email": email,
        "valido": None,
        "status": "indeterminado",
        "mensagem": (
            "Não foi possível confirmar se a caixa postal existe. "
            "O servidor pode bloquear consultas SMTP."
        ),
    }
