from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, email, login, full_name, password, **extra_fields):
        if not email:
            raise ValueError('Email обязателен')
        if not login:
            raise ValueError('Логин обязателен')
        if not full_name:
            raise ValueError('Полное имя обязательно')
        if not password:
            raise ValueError('Пароль обязателен')

        email = self.normalize_email(email)
        user = self.model(email=email, login=login, full_name=full_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, login, full_name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, login, full_name, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=50, unique=True)
    login = models.CharField(max_length=50, unique=True)
    full_name = models.CharField(max_length=50)
    preferences = models.CharField(max_length=100, null=True, blank=True)
    create_date = models.DateField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['login', 'full_name']

    def __str__(self):
        return self.full_name

class Family(models.Model):
    name = models.CharField(max_length=50)
    create_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.name

class FamilyMember(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    family = models.ForeignKey(Family, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, default='member')
    def __str__(self):
        return f"{self.user.full_name} in {self.family.name}"

class FamilyRequests(models.Model):
    PENDING = 'в ожидании'
    ACCEPTED = 'принят'
    DECLINED = 'отклонён'
    STATUS_CHOICES = [
        (PENDING, 'В ожидании'),
        (ACCEPTED, 'Принят'),
        (DECLINED, 'Отклонён'),
    ]
    family = models.ForeignKey(Family, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    create_date = models.DateField(default=timezone.now)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default=PENDING
    )
    def __str__(self):
        return f"Request from {self.user.full_name} to {self.family.name} (Status: {self.status})"

class Place(models.Model):
    coordinates = models.CharField(max_length=30)
    name = models.CharField(max_length=50)
    cost = models.IntegerField(null=True, blank=True)
    category = models.CharField(max_length=100, null=True, blank=True)
    description = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return self.name

class Reviews(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    mark = models.IntegerField()
    text = models.CharField(max_length=500)
    place = models.ForeignKey(Place, on_delete=models.CASCADE)
    id = models.AutoField(primary_key=True)
    def __str__(self):
        return f"Review by {self.user.full_name} for {self.place.name}"

class Trip(models.Model):
    name = models.CharField(max_length=50)
    country = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    family_member = models.ForeignKey(FamilyMember, on_delete=models.CASCADE)
    family = models.ForeignKey(Family, on_delete=models.CASCADE)
    status = models.CharField(max_length=50)
    places = models.ManyToManyField(Place, through='TripPlace', related_name='trips', blank=True)
    def __str__(self):
        return self.name

class TripPlace(models.Model):
    trip = models.ForeignKey(Trip, on_delete=models.CASCADE)
    place = models.ForeignKey(Place, on_delete=models.CASCADE)
    def __str__(self):
        return f"{self.place.name} in {self.trip.name}"