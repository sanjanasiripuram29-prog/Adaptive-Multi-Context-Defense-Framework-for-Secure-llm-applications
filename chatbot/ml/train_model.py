import os
import joblib
import pandas as pd

from sentence_transformers import SentenceTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "training_data.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "random_forest_model.pkl"
)


# Load dataset
print("Loading training data...")

df = pd.read_csv(DATA_PATH)

print("Total samples:", len(df))
print("\nClass distribution:")
print(df["label"].value_counts())


# Separate input and output
prompts = df["prompt"].astype(str).tolist()
labels = df["label"].astype(str).tolist()


# Load Sentence Transformer
print("\nLoading Sentence Transformer...")

embedding_model = SentenceTransformer(
    "all-MiniLM-L6-v2"
)


# Generate embeddings
print("\nGenerating semantic embeddings...")

embeddings = embedding_model.encode(
    prompts,
    show_progress_bar=True
)


# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    embeddings,
    labels,
    test_size=0.2,
    random_state=42,
    stratify=labels
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# Create Random Forest
print("\nTraining Random Forest...")

rf_model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)


# Train
rf_model.fit(X_train, y_train)


# Prediction
print("\nEvaluating model...")

predictions = rf_model.predict(X_test)


# Accuracy
accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nAccuracy:", round(accuracy * 100, 2), "%")


# Detailed report
print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions
    )
)


# Save model
joblib.dump(
    rf_model,
    MODEL_PATH
)


print("\n===================================")
print("Random Forest training completed!")
print("Model saved at:")
print(MODEL_PATH)
print("===================================")