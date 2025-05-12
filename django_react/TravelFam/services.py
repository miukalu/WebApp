from django.db import models
from .models import User, Family, FamilyMember, FamilyRequests, Trip, Reviews, Place, TripPlace

class UserService:
    @staticmethod
    def get_all_users():
        return User.objects.all()

    @staticmethod
    def get_user_by_id(user_id):
        return User.objects.get(id=user_id)

    @staticmethod
    def search_user_by_name(name_query):
        return User.objects.filter(full_name__icontains=name_query)

class TripService:
    @staticmethod
    def get_all_trip():
        return Trip.objects.all()

    @staticmethod
    def search_trip_by_name(name_query):
        return Trip.objects.filter(name__icontains=name_query)

    @staticmethod
    def transfer_trip(title_id, new_family_member):
        title = Trip.objects.get(id=title_id)
        title.family_member = new_family_member
        title.save()