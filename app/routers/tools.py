"""
Standalone "Check & Lookup" tool routes: ad hoc checks that don't require an
asset to be registered first. Each tool wraps an existing scanning service
and renders the result inline on the same page.
"""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.services import (
    abuseipdb_service,
    dns_service,
    reputation_service,
    server_status_service,
    spf_dmarc_service,
    ssl_service,
    whois_service,
)
from app.utils.validators import is_valid_asset_target, is_valid_domain, is_valid_ip, sanitize_text

router = APIRouter(prefix="/tools", tags=["ui"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/blacklist-check")
def blacklist_check_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/blacklist_check.html", {"request": request, "user": user})


@router.post("/blacklist-check")
def blacklist_check_submit(request: Request, target: str = Form(...), user: User = Depends(get_current_user)):
    clean_target = sanitize_text(target, 255).strip()
    error = None
    result = None
    if not is_valid_asset_target(clean_target):
        error = "Please enter a valid domain name or IP address."
    else:
        result = reputation_service.check_reputation(clean_target)
    return templates.TemplateResponse(
        "tools/blacklist_check.html",
        {"request": request, "user": user, "target": clean_target, "result": result, "error": error},
    )


@router.get("/bulk-check")
def bulk_check_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/bulk_check.html", {"request": request, "user": user})


@router.post("/bulk-check")
def bulk_check_submit(request: Request, targets: str = Form(...), user: User = Depends(get_current_user)):
    MAX_TARGETS = 25
    raw_lines = [line.strip() for line in targets.splitlines() if line.strip()]
    lines = raw_lines[:MAX_TARGETS]
    truncated = len(raw_lines) > MAX_TARGETS

    results = []
    for line in lines:
        clean = sanitize_text(line, 255)
        if not is_valid_asset_target(clean):
            results.append({"target": clean, "valid": False})
            continue
        rep = reputation_service.check_reputation(clean)
        results.append({
            "target": clean,
            "valid": True,
            "is_blacklisted": rep["is_blacklisted"],
            "listed_count": len(rep["listed_on"]),
            "total_count": len(rep["checked_providers"]),
        })

    return templates.TemplateResponse(
        "tools/bulk_check.html",
        {"request": request, "user": user, "results": results, "truncated": truncated, "raw_input": targets},
    )


@router.get("/subnet-check")
def subnet_check_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/subnet_check.html", {"request": request, "user": user})


@router.post("/subnet-check")
def subnet_check_submit(request: Request, cidr: str = Form(...), user: User = Depends(get_current_user)):
    import ipaddress

    MAX_HOSTS = 32
    error = None
    results = []
    truncated = False

    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        hosts = list(network.hosts()) or [network.network_address]
        if len(hosts) > MAX_HOSTS:
            truncated = True
            hosts = hosts[:MAX_HOSTS]
        for host in hosts:
            rep = reputation_service.check_reputation(str(host))
            results.append({
                "target": str(host),
                "is_blacklisted": rep["is_blacklisted"],
                "listed_count": len(rep["listed_on"]),
                "total_count": len(rep["checked_providers"]),
            })
    except ValueError:
        error = "Please enter a valid CIDR range, e.g. 203.0.113.0/28."

    return templates.TemplateResponse(
        "tools/subnet_check.html",
        {"request": request, "user": user, "cidr": cidr, "results": results, "error": error, "truncated": truncated, "max_hosts": MAX_HOSTS},
    )


@router.get("/abuseipdb")
def abuseipdb_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(
        "tools/abuseipdb.html",
        {"request": request, "user": user, "configured": abuseipdb_service.is_configured()},
    )


@router.post("/abuseipdb")
def abuseipdb_submit(request: Request, ip: str = Form(...), user: User = Depends(get_current_user)):
    clean_ip = sanitize_text(ip, 64).strip()
    error = None
    result = None
    if not is_valid_ip(clean_ip):
        error = "Please enter a valid IP address."
    else:
        result = abuseipdb_service.check_abuseipdb(clean_ip)
    return templates.TemplateResponse(
        "tools/abuseipdb.html",
        {
            "request": request,
            "user": user,
            "configured": abuseipdb_service.is_configured(),
            "ip": clean_ip,
            "result": result,
            "error": error,
        },
    )


@router.get("/whois")
def whois_tool_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/whois_tool.html", {"request": request, "user": user})


@router.post("/whois")
def whois_tool_submit(request: Request, domain: str = Form(...), user: User = Depends(get_current_user)):
    clean_domain = sanitize_text(domain, 255).strip()
    error = None
    result = None
    if not is_valid_domain(clean_domain):
        error = "Please enter a valid domain name."
    else:
        result = whois_service.lookup_whois(clean_domain)
    return templates.TemplateResponse(
        "tools/whois_tool.html",
        {"request": request, "user": user, "domain": clean_domain, "result": result, "error": error},
    )


@router.get("/dns-records")
def dns_tool_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/dns_tool.html", {"request": request, "user": user})


@router.post("/dns-records")
def dns_tool_submit(request: Request, domain: str = Form(...), user: User = Depends(get_current_user)):
    clean_domain = sanitize_text(domain, 255).strip()
    error = None
    records = None
    if not is_valid_domain(clean_domain):
        error = "Please enter a valid domain name."
    else:
        records = dns_service.lookup_dns_records(clean_domain)
    return templates.TemplateResponse(
        "tools/dns_tool.html",
        {"request": request, "user": user, "domain": clean_domain, "records": records, "error": error},
    )


@router.get("/ssl-checker")
def ssl_tool_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/ssl_tool.html", {"request": request, "user": user})


@router.post("/ssl-checker")
def ssl_tool_submit(request: Request, host: str = Form(...), user: User = Depends(get_current_user)):
    clean_host = sanitize_text(host, 255).strip()
    error = None
    result = None
    if not is_valid_asset_target(clean_host):
        error = "Please enter a valid domain name or IP address."
    else:
        result = ssl_service.check_ssl_certificate(clean_host)
    return templates.TemplateResponse(
        "tools/ssl_tool.html",
        {"request": request, "user": user, "host": clean_host, "result": result, "error": error},
    )


@router.get("/spf-dkim-dmarc")
def spf_tool_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/spf_tool.html", {"request": request, "user": user})


@router.post("/spf-dkim-dmarc")
def spf_tool_submit(
    request: Request,
    domain: str = Form(...),
    dkim_selector: str = Form("default"),
    user: User = Depends(get_current_user),
):
    clean_domain = sanitize_text(domain, 255).strip()
    error = None
    result = None
    if not is_valid_domain(clean_domain):
        error = "Please enter a valid domain name."
    else:
        result = spf_dmarc_service.check_email_security(clean_domain, sanitize_text(dkim_selector, 100) or "default")
    return templates.TemplateResponse(
        "tools/spf_tool.html",
        {"request": request, "user": user, "domain": clean_domain, "dkim_selector": dkim_selector, "result": result, "error": error},
    )


@router.get("/server-status")
def server_status_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("tools/server_status.html", {"request": request, "user": user})


@router.post("/server-status")
def server_status_submit(request: Request, host: str = Form(...), user: User = Depends(get_current_user)):
    clean_host = sanitize_text(host, 255).strip()
    error = None
    result = None
    if not is_valid_asset_target(clean_host):
        error = "Please enter a valid domain name or IP address."
    else:
        result = server_status_service.check_server_status(clean_host)
    return templates.TemplateResponse(
        "tools/server_status.html",
        {"request": request, "user": user, "host": clean_host, "result": result, "error": error},
    )
