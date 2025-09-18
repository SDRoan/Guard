import pathlib, re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score
from joblib import dump

DATA = pathlib.Path("data/train.csv")
OUT = pathlib.Path("models/url_model.joblib")
OUT.parent.mkdir(parents=True, exist_ok=True)

def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    return u.lower()

def main():
    df = pd.read_csv(DATA)
    df["url"] = df["url"].astype(str).map(normalize_url)
    X, y = df["url"].values, df["label"].astype(int).values

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3,5),
                                  lowercase=True, strip_accents="unicode")),
        ("clf", LogisticRegression(max_iter=3000, class_weight="balanced", solver="lbfgs"))
    ])

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    pipe.fit(Xtr, ytr)

    yhat = pipe.predict(Xte)
    ypro = pipe.predict_proba(Xte)[:,1]
    print("ROC AUC:", round(roc_auc_score(yte, ypro), 3))
    print(classification_report(yte, yhat, digits=3))

    dump(pipe, OUT)
    print(f"[✓] Saved model to {OUT}")

if __name__ == "__main__":
    main()
