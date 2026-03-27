"""Tests for l2_classifier/service.py with mocked torch/transformers."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from app.schemas import Label, L2Result


def _mock_torch():
    """Create mock torch module with required attributes."""
    mock = MagicMock()
    mock.device.return_value = MagicMock()
    mock.cuda.is_available.return_value = False
    mock.no_grad.return_value.__enter__ = MagicMock()
    mock.no_grad.return_value.__exit__ = MagicMock()

    import torch
    probs = torch.tensor([[0.8, 0.2]])
    mock.softmax.return_value = probs
    return mock


@pytest.fixture(autouse=True)
def _reset_l2_module():
    """Reset module-level caches before each test."""
    from app.l2_classifier import service
    service._model = None
    service._tokenizer = None
    service._device = None
    yield
    service._model = None
    service._tokenizer = None
    service._device = None


def test_load_model_finetuned():
    """load_model loads from finetuned path if it exists."""
    from app.l2_classifier import service

    mock_tokenizer = MagicMock()
    mock_model = MagicMock()

    with patch("app.l2_classifier.service.Path") as mock_path, \
         patch("app.l2_classifier.service.torch") as mock_torch, \
         patch("app.l2_classifier.service.DistilBertTokenizer") as mock_tok_cls, \
         patch("app.l2_classifier.service.DistilBertForSequenceClassification") as mock_model_cls:

        mock_path.return_value.exists.return_value = True
        mock_torch.cuda.is_available.return_value = False
        mock_torch.device.return_value = "cpu"
        mock_tok_cls.from_pretrained.return_value = mock_tokenizer
        mock_model_cls.from_pretrained.return_value = mock_model

        service.load_model()

        assert service._model is mock_model
        assert service._tokenizer is mock_tokenizer
        mock_model.to.assert_called_once()
        mock_model.eval.assert_called_once()


def test_load_model_fallback_to_base():
    """load_model falls back to base model when finetuned doesn't exist."""
    from app.l2_classifier import service

    with patch("app.l2_classifier.service.Path") as mock_path, \
         patch("app.l2_classifier.service.torch") as mock_torch, \
         patch("app.l2_classifier.service.DistilBertTokenizer") as mock_tok_cls, \
         patch("app.l2_classifier.service.DistilBertForSequenceClassification") as mock_model_cls:

        mock_path.return_value.exists.return_value = False
        mock_torch.cuda.is_available.return_value = False
        mock_torch.device.return_value = "cpu"
        mock_tok_cls.from_pretrained.return_value = MagicMock()
        mock_model_cls.from_pretrained.return_value = MagicMock()

        service.load_model()
        assert service._model is not None


def test_load_model_idempotent():
    """Calling load_model twice doesn't reload."""
    from app.l2_classifier import service

    service._model = MagicMock()
    service._tokenizer = MagicMock()

    with patch("app.l2_classifier.service.DistilBertTokenizer") as mock_tok:
        service.load_model()
        mock_tok.from_pretrained.assert_not_called()


def test_classify_sync():
    """Test synchronous classification with mocked model."""
    import torch
    from app.l2_classifier import service

    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {"input_ids": torch.tensor([[1, 2, 3]]), "attention_mask": torch.tensor([[1, 1, 1]])}

    logits = torch.tensor([[2.0, -1.0]])
    mock_output = MagicMock()
    mock_output.logits = logits

    mock_model = MagicMock()
    mock_model.return_value = mock_output

    service._tokenizer = mock_tokenizer
    service._model = mock_model
    service._device = torch.device("cpu")

    with patch("app.l2_classifier.service.settings") as mock_settings:
        mock_settings.l2_temperature = 1.0
        result = service._classify_sync("Test email text")

    assert isinstance(result, L2Result)
    assert 0.0 <= result.confidence <= 1.0


def test_classify_sync_with_temperature():
    """Test classification with temperature scaling."""
    import torch
    from app.l2_classifier import service

    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {"input_ids": torch.tensor([[1, 2]]), "attention_mask": torch.tensor([[1, 1]])}

    logits = torch.tensor([[1.0, -1.0]])
    mock_output = MagicMock()
    mock_output.logits = logits

    mock_model = MagicMock()
    mock_model.return_value = mock_output

    service._tokenizer = mock_tokenizer
    service._model = mock_model
    service._device = torch.device("cpu")

    with patch("app.l2_classifier.service.settings") as mock_settings:
        mock_settings.l2_temperature = 2.5
        result = service._classify_sync("Test email")

    assert isinstance(result, L2Result)


@pytest.mark.asyncio
async def test_classify_empty_text():
    """Classifying empty text returns default safe result."""
    from app.l2_classifier import service
    service._model = MagicMock()
    service._tokenizer = MagicMock()

    result = await service.classify(body="   ", subject="")
    assert result.label == Label.SAFE
    assert result.confidence == 0.5


@pytest.mark.asyncio
async def test_classify_loads_model_on_demand():
    """classify() auto-loads model if not loaded."""
    import torch
    from app.l2_classifier import service

    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {"input_ids": torch.tensor([[1]]), "attention_mask": torch.tensor([[1]])}
    logits = torch.tensor([[1.5, -0.5]])
    mock_output = MagicMock()
    mock_output.logits = logits
    mock_model = MagicMock()
    mock_model.return_value = mock_output

    with patch("app.l2_classifier.service.load_model") as mock_load:
        def do_load():
            service._model = mock_model
            service._tokenizer = mock_tokenizer
            service._device = torch.device("cpu")
        mock_load.side_effect = do_load

        with patch("app.l2_classifier.service.settings") as mock_s:
            mock_s.l2_temperature = 1.0
            result = await service.classify(body="Hello test", subject="Test")

    assert isinstance(result, L2Result)
