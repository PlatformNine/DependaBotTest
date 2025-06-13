from rest_framework.pagination import CursorPagination
from rest_framework.response import Response
import base64

class CustomCursorPagination(CursorPagination):
    page_size = 10
    ordering = '-id'
    cursor_query_param = 'cursor'

    def encode_cursor(self, cursor):
        if cursor is None:
            return None
        return base64.b64encode(cursor.encode('utf-8')).decode('utf-8')

    def decode_cursor(self, cursor):
        if cursor is None:
            return None
        return base64.b64decode(cursor.encode('utf-8')).decode('utf-8')

    def get_paginated_response(self, data):
        return Response({
            'next': self.encode_cursor(self.get_next_link()),
            'previous': self.encode_cursor(self.get_previous_link()),
            'results': data
        }) 