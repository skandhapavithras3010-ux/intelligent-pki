from src.ipki.dataset import build_training_dataset
from src.ipki.ml import train_model, FEATURE_NAMES


def test_model_training():
    model = train_model()

    assert model.model is not None
    assert len(model.feature_names) == 13


def test_model_can_predict():
    model = train_model()

    X, y = build_training_dataset()

    features = X[0]

    values = [[
        features[name]
        for name in FEATURE_NAMES
    ]]

    prediction = model.model.predict(values)

    assert prediction[0] in [0, 1]


def test_model_probability():
    model = train_model()

    X, y = build_training_dataset()

    features = X[0]

    values = [[
        features[name]
        for name in FEATURE_NAMES
    ]]

    probabilities = model.model.predict_proba(values)

    score = probabilities[0][1] * 100

    assert 0 <= score <= 100