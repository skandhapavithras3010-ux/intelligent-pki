from src.ipki.dataset import build_training_dataset


def test_training_dataset():
    X, y = build_training_dataset()

    assert len(X) == 6
    assert len(y) == 6

    assert all(len(row) == 13 for row in X)

    assert y == [1, 0, 0, 0, 0, 0]