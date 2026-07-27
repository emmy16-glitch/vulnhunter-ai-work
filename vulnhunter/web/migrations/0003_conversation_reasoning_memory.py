from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("web", "0002_conversationthread")]

    operations = [
        migrations.AddField(
            model_name="conversationthread",
            name="reasoning_effort",
            field=models.CharField(
                choices=(("low", "Low"), ("medium", "Medium"), ("high", "High")),
                default="medium",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="conversationthread",
            name="provider_preference",
            field=models.CharField(
                choices=(
                    ("auto", "Automatic"),
                    ("groq", "Groq"),
                    ("huggingface", "Hugging Face"),
                ),
                default="auto",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="conversationthread",
            name="memory_summary",
            field=models.TextField(blank=True, default=""),
        ),
    ]
