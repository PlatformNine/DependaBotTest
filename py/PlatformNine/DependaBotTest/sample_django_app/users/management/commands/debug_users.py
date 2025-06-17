from django.core.management.base import BaseCommand
from users.models import User


class Command(BaseCommand):
    help = 'Debug: List all users in the database'

    def handle(self, *args, **options):
        users = User.objects.all()
        self.stdout.write(f"Found {users.count()} users:")
        for user in users:
            self.stdout.write(f"  ID: {user.id}, Email: {user.email}, Username: {user.username}") 