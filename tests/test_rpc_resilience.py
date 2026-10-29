import unittest
from unittest import mock

from core.req_rpc import ResilientHTTPProvider


class ResilientRPCProviderTests(unittest.TestCase):
    def test_null_receipt_reaches_web3_as_transaction_not_found(self):
        from web3 import Web3
        from web3.exceptions import TransactionNotFound
        provider = ResilientHTTPProvider('http://127.0.0.1:1', attempts=3, backoff_initial_seconds=0)
        with mock.patch('core.req_rpc.HTTPProvider.make_request', return_value={
                'jsonrpc': '2.0', 'id': 1, 'result': None}) as request:
            with self.assertRaises(TransactionNotFound):
                Web3(provider).eth.get_transaction_receipt('0x'+'12'*32)
        self.assertEqual(request.call_count, 1)

    def test_null_transaction_lookup_does_not_make_null_contract_result_valid(self):
        provider = ResilientHTTPProvider('http://127.0.0.1:1', attempts=2, backoff_initial_seconds=0)
        with mock.patch('core.req_rpc.HTTPProvider.make_request', return_value={
                'jsonrpc': '2.0', 'id': 1, 'result': None}):
            self.assertIsNone(provider.make_request('eth_getTransactionByHash', [])['result'])
            with self.assertRaises(ConnectionError): provider.make_request('eth_call', [])

    def test_read_retries_but_contract_error_is_returned(self):
        provider = ResilientHTTPProvider(
            "http://127.0.0.1:1", attempts=3, backoff_initial_seconds=0
        )
        contract_error = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": 3, "message": "execution reverted"},
        }
        with mock.patch(
            "core.req_rpc.HTTPProvider.make_request",
            side_effect=[ConnectionError("closed"), contract_error],
        ) as request:
            result = provider.make_request("eth_call", [])
        self.assertEqual(contract_error, result)
        self.assertEqual(2, request.call_count)

    def test_transaction_submission_is_never_retried(self):
        provider = ResilientHTTPProvider(
            "http://127.0.0.1:1", attempts=4, backoff_initial_seconds=0
        )
        with mock.patch(
            "core.req_rpc.HTTPProvider.make_request",
            side_effect=ConnectionError("response lost"),
        ) as request:
            with self.assertRaises(ConnectionError):
                provider.make_request("eth_sendRawTransaction", ["0x01"])
        self.assertEqual(1, request.call_count)


if __name__ == "__main__":
    unittest.main()
