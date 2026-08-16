from django.apps import AppConfig


class VulnHunterWebConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "vulnhunter.web"
    verbose_name = "VulnHunter Web"

    def ready(self) -> None:
        # Presentation/session hooks keep the workspace chat-first; provider routing
        # remains advisory-only. Deterministic authorization/execution controls stay
        # inside their existing governed services.
        from vulnhunter.web.ai_failover import install as install_ai_failover
        from vulnhunter.web.chat_experience import install as install_chat_experience

        install_ai_failover()
        install_chat_experience()
