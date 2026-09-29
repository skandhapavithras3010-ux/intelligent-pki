import json


def make_json_report(result):
    report = {
        "certificate": {
            "subject": result["cert"].subject,
            "issuer": result["cert"].issuer,
            "sha256": result["cert"].sha256,
        },
        "chain_status": result["chain"].status,
        "policy": [
            {
                "rule": item.rule,
                "status": item.status,
                "message": item.message,
            }
            for item in result["policy"]
        ],
        "ml_score": round(result["ml_score"], 2),
        "final_score": round(result["fusion"].score, 2),
        "verdict": result["fusion"].verdict,
        "explanations": result["explanations"],
    }

    return json.dumps(report, indent=2)