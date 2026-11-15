import pytest

def test_get_reports_list(client):
    res = client.get("/api/reports")
    assert res.status_code == 200
    reports = res.json()
    assert isinstance(reports, list)
    assert len(reports) >= 3
    titles = [r["title"] for r in reports]
    assert any("Ransomware" in t for t in titles)
    assert any("Hardening" in t for t in titles)

def test_generate_report_and_download_pdf(client):
    # Generate new report
    gen_res = client.post("/api/reports/generate")
    assert gen_res.status_code == 200
    report = gen_res.json()
    assert "id" in report
    assert "summary" in report
    assert "timeline" in report
    assert "recommendations" in report
    assert report["has_pdf"] is True

    # Download PDF
    pdf_res = client.get(f"/api/reports/{report['id']}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000 # Valid non-empty PDF bytes
    assert pdf_res.content[:4] == b"%PDF"

def test_download_nonexistent_pdf(client):
    res = client.get("/api/reports/nonexistent_rep_99/pdf")
    assert res.status_code == 404
