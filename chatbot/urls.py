from django.urls import path
from . import views


urlpatterns = [

    path(
        "",
        views.landing,
        name="home"
    ),

    path(
        "login/",
        views.login_view,
        name="login"
    ),

    path(
        "register/",
        views.register_view,
        name="register"
    ),

    path(
        "dashboard/",
        views.dashboard,
        name="dashboard"
    ),

    path(
        "chat/",
        views.chat,
        name="chat"
    ),

    path(
        "logout/",
        views.logout_view,
        name="logout"
    ),

    path(
        "dashboard-stats/",
        views.dashboard_stats,
        name="dashboard_stats"
    ),

    path(
        "prompt-logs/",
        views.prompt_logs,
        name="prompt_logs"
    ),

    path(
        "attack-logs/",
        views.attack_logs,
        name="attack_logs"
    ),
    path(
    "generate-response/",
    views.generate_response,
    name="generate_response"
),
]