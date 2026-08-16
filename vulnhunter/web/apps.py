from django.apps import AppConfig


class VulnHunterWebConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "vulnhunter.web"
    verbose_name = "VulnHunter Web"

    def ready(self) -> None:
        # Install the advisory-only provider router after Django has loaded the app.
        # Deterministic authorization/execution controls remain untouched.
        from vulnhunter.web.ai_failover import install

        install()
