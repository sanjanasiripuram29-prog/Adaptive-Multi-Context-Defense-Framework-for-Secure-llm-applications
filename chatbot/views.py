# chatbot/views.py

import json

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt

from .models import SecurityLog
from .services import SecurityEngine
import time


# Reuse one security engine instance across requests.
# The heavy ML models are cached by services.get_models().
security_engine = SecurityEngine()


# =========================================================
# HOME
# =========================================================

def landing(request):

    return render(
        request,
        "chatbot/index.html"
    )


def home(request):

    return render(
        request,
        "chatbot/index.html"
    )


# =========================================================
# LOGIN
# =========================================================

def login_view(request):

    if request.user.is_authenticated:

        return redirect(
            "/dashboard/"
        )

    if request.method == "POST":

        username = request.POST.get(
            "username",
            ""
        ).strip()

        password = request.POST.get(
            "password",
            ""
        )

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is not None:

            login(
                request,
                user
            )

            return redirect(
                "/dashboard/"
            )

        return render(
            request,
            "chatbot/login.html",
            {
                "error":
                    "Invalid username or password."
            }
        )

    return render(
        request,
        "chatbot/login.html"
    )


# =========================================================
# REGISTER
# =========================================================

def register_view(request):

    if request.user.is_authenticated:

        return redirect(
            "/dashboard/"
        )

    if request.method == "POST":

        username = request.POST.get(
            "username",
            ""
        ).strip()

        email = request.POST.get(
            "email",
            ""
        ).strip()

        password = request.POST.get(
            "password",
            ""
        )

        confirm_password = request.POST.get(
            "confirm_password",
            ""
        )

        if not username:

            return render(
                request,
                "chatbot/register.html",
                {
                    "error":
                        "Username is required."
                }
            )

        if not password:

            return render(
                request,
                "chatbot/register.html",
                {
                    "error":
                        "Password is required."
                }
            )

        if password != confirm_password:

            return render(
                request,
                "chatbot/register.html",
                {
                    "error":
                        "Passwords do not match."
                }
            )

        if User.objects.filter(
            username=username
        ).exists():

            return render(
                request,
                "chatbot/register.html",
                {
                    "error":
                        "Username already exists."
                }
            )

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        login(
            request,
            user
        )

        return redirect(
            "/dashboard/"
        )

    return render(
        request,
        "chatbot/register.html"
    )


# =========================================================
# LOGOUT
# =========================================================

def logout_view(request):

    logout(request)

    return redirect("/")


# =========================================================
# DASHBOARD
# =========================================================

@login_required(login_url="/login/")
def dashboard(request):

    return render(
        request,
        "chatbot/dashboard.html"
    )


# =========================================================
# CHAT / SECURITY PIPELINE
# =========================================================

@csrf_exempt
@login_required(login_url="/login/")
def chat(request):

    try:

        # =================================================
        # REQUEST METHOD
        # =================================================

        if request.method != "POST":

            return JsonResponse(
                {
                    "success": False,
                    "error":
                        "Only POST requests are allowed."
                },
                status=405
            )

        # =================================================
        # READ JSON
        # =================================================

        try:

            body = json.loads(
                request.body.decode(
                    "utf-8"
                )
            )

        except Exception:

            return JsonResponse(
                {
                    "success": False,
                    "error":
                        "Invalid JSON request."
                },
                status=400
            )

        # =================================================
        # GET PROMPT
        # =================================================

        prompt = str(
            body.get(
                "prompt",
                ""
            )
        ).strip()

        if not prompt:

            return JsonResponse(
                {
                    "success": False,
                    "error":
                        "Prompt cannot be empty."
                },
                status=400
            )

        # =================================================
        # SECURITY ANALYSIS
        # =================================================

        analysis_start = time.perf_counter()

        # Reuse the same engine instance. ML models are cached in services.py.
        analysis = security_engine.analyze(
            prompt
        )

        analysis_time = time.perf_counter() - analysis_start

        print(
            f"SECURITY ANALYSIS TIME: {analysis_time:.2f} seconds"
        )

        # =================================================
        # GET SANITIZED PROMPT
        # =================================================

        sanitized_prompt = analysis.get(
            "sanitized_prompt",
            prompt
        )

        sanitizer_changed = analysis.get(
            "sanitizer_changed",
            False
        )

        # =================================================
        # RANDOM FOREST
        # =================================================

        random_forest = analysis.get(
            "random_forest",
            {}
        )

        # =================================================
        # RISK
        # =================================================

        risk_score = int(
            analysis.get(
                "risk_score",
                5
            )
        )

        # =================================================
        # TRUST
        # =================================================

        trust_score = max(
            0,
            min(
                100,
                100 - risk_score
            )
        )

        # =================================================
        # SECURITY INFORMATION
        # =================================================

        context = analysis.get(
            "context",
            {}
        )

        semantic = analysis.get(
            "semantic",
            {}
        )

        reputation = analysis.get(
            "reputation",
            {}
        )

        sanitizer = analysis.get(
            "sanitizer",
            {}
        )

        threats = analysis.get(
            "threats",
            []
        )

        # =================================================
        # ATTACK INFORMATION
        # =================================================

        attack_detected = bool(
            context.get(
                "attack_detected",
                False
            )
        )

        attack_type = (
            context.get(
                "threat_type",
                ""
            )
            or
            ""
        )

        # =================================================
        # DECISION
        # =================================================

        decision = analysis.get(
            "decision",
            "ALLOW"
        )

        # =================================================
        # MCP STATUS
        # =================================================

        mcp_status = context.get(
            "result",
            "PASSED"
        )

        # =================================================
        # SEMANTIC STATUS
        # =================================================

        semantic_status = semantic.get(
            "result",
            "CONSISTENT"
        )

        # =================================================
        # REPUTATION
        # =================================================

        reputation_status = reputation.get(
            "level",
            "TRUSTED"
        )

        # =================================================
        # SANITIZER
        # =================================================

        sanitizer_status = (
            "SANITIZED"
            if sanitizer_changed
            else
            "UNCHANGED"
        )

        # =================================================
        # SAVE LOG
        # =================================================

        SecurityLog.objects.create(
            user=request.user,
            prompt=prompt,
            sanitized_prompt=sanitized_prompt,
            risk_score=risk_score,
            trust_score=trust_score,
            decision=decision,
            attack_type=attack_type,
            mcp_status=mcp_status,
            semantic_status=semantic_status,
            reputation_status=reputation_status,
            sanitizer_status=sanitizer_status
        )

        # =================================================
        # RESPONSE
        # =================================================

        return JsonResponse(
            {
                "success":
                    True,

                "prompt":
                    prompt,

                # AI response is generated by /generate-response/
                # after the security analysis is complete.
                "response":
                    None,

                "sanitized_prompt":
                    sanitized_prompt,

                "sanitizer_changed":
                    sanitizer_changed,

                "sanitizer":
                    sanitizer,

                "mcp":
                    context,

                "semantic":
                    semantic,

                "reputation":
                    reputation,

                # =================================================
                # RANDOM FOREST RESULT
                # =================================================

                "random_forest":
                    random_forest,

                "risk_score":
                    risk_score,

                "trust_score":
                    trust_score,

                "security_level":
                    analysis.get(
                        "security_level",
                        "LOW"
                    ),

                "decision":
                    decision,

                "attack_detected":
                    attack_detected,

                "attack_type":
                    attack_type,

                "threats":
                    threats
            },
            status=200
        )

    except Exception as e:

        import traceback

        traceback.print_exc()

        return JsonResponse(
            {
                "success":
                    False,

                "error":
                    "Security pipeline error: "
                    + str(e)
            },
            status=500
        )


# =========================================================
# GENERATE SECURE AI RESPONSE
# =========================================================

@csrf_exempt
@login_required(login_url="/login/")
def generate_response(request):

    try:

        if request.method != "POST":
            return JsonResponse(
                {
                    "success": False,
                    "error": "Only POST requests are allowed."
                },
                status=405
            )

        try:
            body = json.loads(
                request.body.decode("utf-8")
            )
        except Exception:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Invalid JSON request."
                },
                status=400
            )

        sanitized_prompt = str(
            body.get("sanitized_prompt", "")
        ).strip()

        if not sanitized_prompt:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Sanitized prompt cannot be empty."
                },
                status=400
            )

        print("\n========================================")
        print("GENERATE SECURE AI RESPONSE")
        print("SANITIZED PROMPT:", sanitized_prompt)
        print("========================================")

        # The LLM receives ONLY the sanitized prompt.
        llm_start = time.perf_counter()

        response_text = security_engine.generate_response(
            sanitized_prompt
        )

        llm_time = time.perf_counter() - llm_start

        print(
            f"LLM GENERATION TIME: {llm_time:.2f} seconds"
        )

        print("AI RESPONSE GENERATED")
        print("RESPONSE:", response_text)
        print("========================================\n")

        return JsonResponse(
            {
                "success": True,
                "response": response_text
            },
            status=200
        )

    except Exception as e:

        import traceback
        traceback.print_exc()

        return JsonResponse(
            {
                "success": False,
                "error": "AI response generation error: " + str(e)
            },
            status=500
        )


# =========================================================
# DASHBOARD STATISTICS
# =========================================================

@login_required(login_url="/login/")
def dashboard_stats(request):

    try:

        logs = SecurityLog.objects.filter(
            user=request.user
        )

        total_prompts = logs.count()

        total_attacks = logs.filter(
            decision__in=[
                "BLOCK",
                "BLOCKED",
                "SANITIZE",
                "REVIEW"
            ]
        ).count()

        risk_values = list(
            logs.values_list(
                "risk_score",
                flat=True
            )
        )

        trust_values = list(
            logs.values_list(
                "trust_score",
                flat=True
            )
        )

        if risk_values:

            average_risk = round(
                sum(risk_values)
                /
                len(risk_values)
            )

        else:

            average_risk = 0

        if trust_values:

            average_trust = round(
                sum(trust_values)
                /
                len(trust_values)
            )

        else:

            average_trust = 100

        # =================================================
        # ATTACK TYPES
        # =================================================

        attack_types = {}

        for log in logs:

            if log.decision in [
                "BLOCK",
                "BLOCKED",
                "SANITIZE",
                "REVIEW"
            ]:

                attack_type = (
                    log.attack_type
                    or
                    "SECURITY EVENT"
                )

                attack_types[attack_type] = (
                    attack_types.get(
                        attack_type,
                        0
                    )
                    +
                    1
                )

        return JsonResponse(
            {
                "success":
                    True,

                "total_prompts":
                    total_prompts,

                "total_attacks":
                    total_attacks,

                "average_risk":
                    average_risk,

                "average_trust":
                    average_trust,

                "attack_types":
                    attack_types
            }
        )

    except Exception as e:

        return JsonResponse(
            {
                "success":
                    False,

                "error":
                    str(e)
            },
            status=500
        )


# =========================================================
# PROMPT LOGS
# =========================================================

@login_required(login_url="/login/")
def prompt_logs(request):

    try:

        logs = SecurityLog.objects.filter(
            user=request.user
        ).order_by(
            "-created_at"
        )[:100]

        result = []

        for log in logs:

            result.append(
                {
                    "id":
                        log.id,

                    "created_at":
                        log.created_at.strftime(
                            "%d-%m-%Y %H:%M"
                        ),

                    "prompt":
                        log.prompt,

                    "sanitized_prompt":
                        getattr(
                            log,
                            "sanitized_prompt",
                            ""
                        ),

                    "risk_score":
                        log.risk_score,

                    "trust_score":
                        log.trust_score,

                    "decision":
                        log.decision,

                    "attack_type":
                        getattr(
                            log,
                            "attack_type",
                            ""
                        ),

                    "mcp_status":
                        getattr(
                            log,
                            "mcp_status",
                            ""
                        ),

                    "semantic_status":
                        getattr(
                            log,
                            "semantic_status",
                            ""
                        ),

                    "reputation_status":
                        getattr(
                            log,
                            "reputation_status",
                            ""
                        ),

                    "sanitizer_status":
                        getattr(
                            log,
                            "sanitizer_status",
                            ""
                        )
                }
            )

        return JsonResponse(
            {
                "success":
                    True,

                "logs":
                    result
            }
        )

    except Exception as e:

        return JsonResponse(
            {
                "success":
                    False,

                "error":
                    str(e)
            },
            status=500
        )


# =========================================================
# ATTACK LOGS
# =========================================================

@login_required(login_url="/login/")
def attack_logs(request):

    try:

        logs = SecurityLog.objects.filter(
            user=request.user,
            decision__in=[
                "BLOCK",
                "BLOCKED",
                "SANITIZE",
                "REVIEW"
            ]
        ).order_by(
            "-created_at"
        )[:100]

        result = []

        for log in logs:

            result.append(
                {
                    "id":
                        log.id,

                    "created_at":
                        log.created_at.strftime(
                            "%d-%m-%Y %H:%M"
                        ),

                    "prompt":
                        log.prompt,

                    "sanitized_prompt":
                        getattr(
                            log,
                            "sanitized_prompt",
                            ""
                        ),

                    "attack_type":
                        getattr(
                            log,
                            "attack_type",
                            ""
                        )
                        or
                        "SECURITY EVENT",

                    "risk_score":
                        log.risk_score,

                    "trust_score":
                        log.trust_score,

                    "decision":
                        log.decision
                }
            )

        return JsonResponse(
            {
                "success":
                    True,

                "attacks":
                    result
            }
        )

    except Exception as e:

        return JsonResponse(
            {
                "success":
                    False,

                "error":
                    str(e)
            },
            status=500
        )