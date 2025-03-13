from django.core.management.base import BaseCommand
from TravelFam.models import User, Family, FamilyMember, Place, Reviews, Trip, TripPlace
from django.utils import timezone

class Command(BaseCommand):
    help = 'Fill the database with test data'

    def handle(self, *args, **kwargs):
        user = User.objects.create_user(
            email='user@example.com',
            login='user123',
            full_name='John Doe',
            password='securepassword123'
        )

        family = Family.objects.create(name='Smith Family')

        family_member = FamilyMember.objects.create(
            user=user,
            family=family,
            role='Parent'
        )

        place = Place.objects.create(
            coordinates='40.7128,-74.0060',
            name='Central Park',
            cost=0,
            category='Park',
            description='A large park in NYC'
        )

        trip = Trip.objects.create(
            name='Summer Vacation',
            country='USA',
            city='New York',
            start_date=timezone.now(),
            end_date=timezone.now(),
            family_member=family_member,
            family=family,
            status='Planned'
        )

        TripPlace.objects.create(trip=trip, place=place)

        Reviews.objects.create(
            user=user,
            mark=5,
            text='Great place!',
            place=place
        )

        self.stdout.write(self.style.SUCCESS('Database filled successfully!'))