import json
import os
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

HISTORY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "history.json")

def _ensure_data_dir():
    """Crée le dossier data/ s'il n'existe pas."""
    data_dir = os.path.dirname(HISTORY_FILE)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        logger.info(f"Dossier créé : {data_dir}")

def save_to_history(
    user_id: str,
    prompt: str,
    status: str,
    tokens_used: int,
    type: str = "Pipeline",
    error_message: str = ""
):
    """
    Enregistre une nouvelle entrée dans l'historique JSON.
    """
    _ensure_data_dir()
    
    entry = {
        "id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),
        "user_id": user_id,
        "prompt": prompt[:100],  # On ne garde que le début du prompt
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tokens_used": tokens_used,
        "type": type,
        "error_message": error_message
    }
    
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception as e:
            logger.error(f"Erreur lecture historique : {e}")
            history = []
            
    history.insert(0, entry)  # Plus récent en premier
    
    # Limiter à 100 entrées pour éviter de saturer le JSON
    history = history[:100]
    
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erreur écriture historique : {e}")

def get_user_history(user_id: str, role: str) -> List[Dict[str, Any]]:
    """
    Récupère l'historique filtré par rôle.
    - admin : tout l'historique
    - user : seulement ses propres pipelines
    """
    if not os.path.exists(HISTORY_FILE):
        return []
        
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
            
        if role == "admin":
            return history
        
        return [h for h in history if h.get("user_id") == user_id]
    except Exception as e:
        logger.error(f"Erreur lecture historique : {e}")
        return []
