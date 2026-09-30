"""
Machine Learning Engine
------------------------
Computes TF-IDF embeddings on normalized log messages and runs an unsupervised
scikit-learn Isolation Forest to flag novel / statistically anomalous log events.
"""

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest


def run_anomaly_detection(df, contamination=0.05, message_col="message", random_state=42):
    """
    Adds two columns to df:
      - ml_anomaly (bool): True if Isolation Forest flagged the event as an outlier (-1)
      - anomaly_score (float): continuous outlier score (lower = more anomalous)

    Returns the augmented dataframe.
    """
    df = df.copy()
    n = len(df)

    if n < 5:
        # Not enough data for a meaningful model — mark everything as normal.
        df["ml_anomaly"] = False
        df["anomaly_score"] = 0.0
        return df

    messages = df[message_col].fillna("").astype(str).tolist()

    vectorizer = TfidfVectorizer(
        max_features=800,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=1,
    )
    try:
        X = vectorizer.fit_transform(messages)
    except ValueError:
        df["ml_anomaly"] = False
        df["anomaly_score"] = 0.0
        return df

    # Isolation Forest works fine on sparse matrices for recent sklearn versions;
    # densify defensively for smaller datasets where memory isn't a concern.
    X_dense = X.toarray() if X.shape[0] * X.shape[1] < 5_000_000 else X

    contamination = float(np.clip(contamination, 0.01, 0.5))

    clf = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_dense)

    preds = clf.predict(X_dense)          # -1 = anomaly, 1 = normal
    scores = clf.decision_function(X_dense)  # higher = more normal, lower = more anomalous

    df["ml_anomaly"] = preds == -1
    df["anomaly_score"] = scores.round(4)
    return df
