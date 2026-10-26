from django.db import models
from django.contrib.auth.models import User


class SecurityLog(models.Model):

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="security_logs"
    )

    prompt = models.TextField()

    sanitized_prompt = models.TextField(
        blank=True,
        default=""
    )

    risk_score = models.FloatField(
        default=0
    )

    trust_score = models.FloatField(
        default=100
    )

    decision = models.CharField(
        max_length=30,
        default="ALLOW"
    )

    attack_type = models.CharField(
        max_length=100,
        blank=True,
        default=""
    )

    mcp_status = models.CharField(
        max_length=30,
        default="WAITING"
    )

    semantic_status = models.CharField(
        max_length=30,
        default="WAITING"
    )

    reputation_status = models.CharField(
        max_length=30,
        default="WAITING"
    )

    sanitizer_status = models.CharField(
        max_length=30,
        default="WAITING"
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.user.username} - {self.decision} - {self.risk_score}%"