from typing import List
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic.v1 import EmailStr, BaseModel
from .config import settings
from jinja2 import Environment, select_autoescape, PackageLoader


env = Environment(
    loader=PackageLoader('app', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)


class EmailSchema(BaseModel):
    email: List[EmailStr]


class Email:
    def __init__(self, user: dict, url: str, email: List[EmailStr]):
        self.name = user['full_name']
        self.sender = 'MrAdmin <admin@admin.com>'
        self.email = email
        self.url = url
        pass

    async def send_email(self, subject, template):
        conf = ConnectionConfig(
            MAIL_USERNAME=settings.EMAIL_USERNAME,
            MAIL_PASSWORD=settings.EMAIL_PASSWORD,
            MAIL_FROM=settings.EMAIL_FROM,
            MAIL_PORT=settings.EMAIL_PORT,
            MAIL_SERVER=settings.EMAIL_HOST,
            MAIL_STARTTLS=False,
            MAIL_SSL_TLS=False,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=True
        )
        template = env.get_template(f'{template}.html')

        html = template.render(
            url=self.url,
            first_name=self.name,
            subject=subject
        )

        message = MessageSchema(
            subject=subject,
            recipients=self.email,
            body=html,
            subtype="html"
        )

        fm = FastMail(conf)
        await fm.send_message(message)

    async def send_verification_code(self):
        await self.send_email('Your verification code (Valid for 10min)', 'verification')
