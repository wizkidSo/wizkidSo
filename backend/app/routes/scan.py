from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.scan import EmailScanRequest
from app.services.email_analyzer import analyze_email

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.schemas.scan import URLScanRequest
from app.services.url_analyzer import analyze_url


router = APIRouter(
    prefix="/scan",
    tags=["Scanning"]
)


@router.post("/url")
def scan_url(
    scan_data: URLScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    url = scan_data.url.strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty"
        )

    analysis = analyze_url(url)

    new_scan = Scan(
        user_id=current_user.id,
        scan_type="URL",
        input_data=url,
        result=analysis["result"],
        risk_score=analysis["risk_score"],
        explanation=analysis["explanation"]
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return {
        "scan_id": new_scan.id,
        "scan_type": "URL",
        "url": analysis["url"],
        "result": analysis["result"],
        "risk_score": analysis["risk_score"],
        "explanation": analysis["explanation"],
        "indicators": analysis["indicators"]
    }
@router.get("/history")
def get_scan_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )

    return {
        "total_scans": len(scans),
        "scans": [
            {
                "scan_id": scan.id,
                "scan_type": scan.scan_type,
                "input_data": scan.input_data,
                "result": scan.result,
                "risk_score": scan.risk_score,
                "explanation": scan.explanation,
                "created_at": (
                    scan.created_at.isoformat()
                    if scan.created_at else None
                )
            }
            for scan in scans
        ]
    }
@router.post("/email")
def scan_email(
    email_data: EmailScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    email_text = email_data.email_text.strip()

    if not email_text:
        raise HTTPException(
            status_code=400,
            detail="Email content cannot be empty."
        )

    analysis = analyze_email(email_text)

    new_scan = Scan(
        user_id=current_user.id,
        scan_type="EMAIL",
        input_data=email_text,
        result=analysis["result"],
        risk_score=analysis["risk_score"],
        explanation=analysis["explanation"]
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return {
        "scan_id": new_scan.id,
        "scan_type": "EMAIL",
        "result": analysis["result"],
        "risk_score": analysis["risk_score"],
        "explanation": analysis["explanation"],
        "indicators": analysis["indicators"],
        "extracted_urls": analysis["extracted_urls"],
        "recommendations": analysis["recommendations"]
    }