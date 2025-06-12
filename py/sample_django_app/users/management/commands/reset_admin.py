from django.core.management.base import BaseCommand
from users.models import User

class Command(BaseCommand):
    help = 'Resets the admin user password to "yoda"'

    def handle(self, *args, **options):
        try:
            admin = User.objects.get(email='admin@yodaexample.click')
            admin.set_password('yoda')
            admin.save()
            self.stdout.write(self.style.SUCCESS('Successfully reset admin password'))
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR('Admin user not found')) 