from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404, render, redirect
from django.http import Http404
from django.contrib import messages
import jwt
from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import User, Family, FamilyMember, FamilyRequests, Place, Reviews, Trip, TripPlace
from .serializers import (UserRegistrationSerializer, UserSerializer, FamilySerializer, FamilyMemberSerializer, FamilyRequestSerializer,
                          PlaceSerializer, ReviewSerializer, TripSerializer, UserLogoutSerializer, ChangePasswordSerializer)
import requests
from django.urls import reverse

class UserLoginView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]

class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer

class UserLogoutView(generics.GenericAPIView):
    serializer_class = UserLogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'status': 'logged out'}, status=status.HTTP_200_OK)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    lookup_url_kwarg = 'user_id'

    def retrieve(self, request, *args, **kwargs):
        user = get_object_or_404(User, id=self.kwargs['user_id'])
        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        user = get_object_or_404(User, id=self.kwargs['user_id'])
        if 'email' in request.data or 'password' in request.data:
            return Response(
                {"error": "Email and password cannot be changed here"},
                status=status.HTTP_400_BAD_REQUEST
            )
        valid_fields = {'login', 'full_name', 'preferences'}
        invalid_fields = set(request.data.keys()) - valid_fields
        if invalid_fields:
            return Response(
                {"error": f"Invalid fields to update: {', '.join(invalid_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        model_fields = {field.name for field in User._meta.get_fields()}
        non_existent_fields = set(request.data.keys()) - model_fields
        if non_existent_fields:
            return Response(
                {"error": f"Fields do not exist in User model: {', '.join(non_existent_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def change_password(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not user.check_password(serializer.validated_data['current_password']):
            return Response({'error': 'current password is incorrect'},
                            status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({'status': 'password changed'},
                        status=status.HTTP_200_OK)

class FamilyViewSet(viewsets.ModelViewSet):
    queryset = Family.objects.all()
    serializer_class = FamilySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

class FamilyMemberViewSet(viewsets.ModelViewSet):
    queryset = FamilyMember.objects.all()
    serializer_class = FamilyMemberSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        family_id = self.kwargs.get('family_id')
        if self.request.user.is_superuser:
            return FamilyMember.objects.filter(family_id=family_id)
        if not FamilyMember.objects.filter(
                family_id=family_id,
                user=self.request.user
        ).exists():
            raise PermissionDenied("You are not a member of this family")

        return FamilyMember.objects.filter(family_id=family_id)

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, obj)
        return obj

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        current_user_member = get_object_or_404(FamilyMember, user=request.user, family_id=self.kwargs.get('family_id'))
        if request.user.is_superuser:
            pass
        elif current_user_member.role == 'creator':
            pass
        elif instance.user != request.user:
            raise PermissionDenied("You can only remove yourself from the family")

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class FamilyRequestViewSet(viewsets.ModelViewSet):
    queryset = FamilyRequests.objects.all()
    serializer_class = FamilyRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        family_id = self.kwargs.get('family_id')
        if family_id:
            return self.queryset.filter(family_id=family_id)
        return self.queryset.none()

    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None, *args, **kwargs):
        family_id = self.kwargs.get('family_id')
        user_id = self.kwargs.get('user_id')
        role = request.data.get('role', 'member')
        family = get_object_or_404(Family, pk=family_id)
        user = get_object_or_404(User, pk=user_id)
        request_obj = get_object_or_404(
            FamilyRequests,
            family_id=family_id,
            user_id=user_id,
            status=FamilyRequests.PENDING
        )
        request_obj.status = FamilyRequests.ACCEPTED
        request_obj.save()
        member, created = FamilyMember.objects.update_or_create(
            user_id=user_id,
            family_id=family_id,
            defaults={'role': role}
            # role=role
        )
        return Response({'status': 'request accepted'},
                        status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def decline(self, request, pk=None, *args, **kwargs):
        family_id = self.kwargs.get('family_id')
        user_id = self.kwargs.get('user_id')
        family = get_object_or_404(Family, pk=family_id)
        user = get_object_or_404(User, pk=user_id)
        request_obj = get_object_or_404(
            FamilyRequests,
            family_id=family_id,
            user_id=user_id,
            status=FamilyRequests.PENDING
        )
        request_obj.status = FamilyRequests.DECLINED
        request_obj.save()
        return Response(
            {'status': 'request declined'},
            status=status.HTTP_200_OK
        )

class PlaceViewSet(viewsets.ModelViewSet):
    queryset = Place.objects.all()
    serializer_class = PlaceSerializer
    permission_classes = [permissions.IsAuthenticated]

class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Reviews.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if 'place_id' in self.kwargs:
            return Reviews.objects.filter(place_id=self.kwargs['place_id'])
        return super().get_queryset()
    def perform_create(self, serializer):
        if 'place_id' in self.kwargs:
            serializer.save(
                user=self.request.user,
                place_id=self.kwargs['place_id']
            )
        else:
            serializer.save(user=self.request.user)


class TripViewSet(viewsets.ModelViewSet):
    queryset = Trip.objects.all()
    serializer_class = TripSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

    @action(detail=True, methods=['post'])
    def repeat(self, request, pk=None):
        original_trip = self.get_object()
        if not original_trip.family.familymember_set.filter(user=request.user).exists():
            return Response(
                {"error": "You are not a member of this family"},
                status=status.HTTP_403_FORBIDDEN
            )
        new_trip = Trip.objects.create(
            name=f"{original_trip.name} (Copy)",
            country=original_trip.country,
            city=original_trip.city,
            start_date=original_trip.start_date,
            end_date=original_trip.end_date,
            family=original_trip.family,
            family_member=FamilyMember.objects.get(
                user=request.user,
                family=original_trip.family
            ),
            status='planned'
        )
        for trip_place in original_trip.trip_places.all():
            TripPlace.objects.create(
                trip=new_trip,
                place=trip_place.place
            )
        return Response(
            self.get_serializer(new_trip).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def add_place(self, request, pk=None):
        trip = self.get_object()
        place_id = request.data.get('place_id')
        if not place_id:
            return Response(
                {"error": "place_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not trip.family.familymember_set.filter(user=request.user).exists():
            return Response(
                {"error": "You are not a member of this family"},
                status=status.HTTP_403_FORBIDDEN
            )
        place = get_object_or_404(Place, id=place_id)
        TripPlace.objects.get_or_create(trip=trip, place=place)
        return Response(
            {"status": "Place added"},
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['delete'])
    def remove_place(self, request, pk=None):
        trip = self.get_object()
        place_id = request.data.get('place_id')
        if not place_id:
            return Response(
                {"error": "place_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not trip.family.familymember_set.filter(user=request.user).exists():
            return Response(
                {"error": "You are not a member of this family"},
                status=status.HTTP_403_FORBIDDEN
            )
        place = get_object_or_404(Place, id=place_id)
        TripPlace.objects.filter(trip=trip, place=place).delete()
        return Response(
            status=status.HTTP_204_NO_CONTENT
        )

    @action(detail=True, methods=['get'])
    def places(self, request, pk=None):
        trip = self.get_object()
        trip_places = TripPlace.objects.filter(trip=trip).select_related('place')
        serializer = PlaceSerializer([tp.place for tp in trip_places], many=True)
        return Response(serializer.data)

class UserFamiliesView(generics.ListAPIView):
    serializer_class = FamilySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs['user_id']
        user = get_object_or_404(User, pk=user_id)
        return Family.objects.filter(familymember__user=user)

class UserTripsView(generics.ListAPIView):
    serializer_class = TripSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs['user_id']
        user = get_object_or_404(User, pk=user_id)
        return Trip.objects.filter(family__familymember__user=user)

class PlaceFilterView(generics.ListAPIView):
    serializer_class = PlaceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        category = self.request.query_params.get('category')
        if category:
            places = Place.objects.filter(category__icontains=category)
            if not places.exists():
                raise Http404("Category does not exist")
            return places
        return Place.objects.all()

class ReviewFilterView(generics.ListAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        mark = self.request.query_params.get('mark')
        if mark:
            reviews = Reviews.objects.filter(mark=mark)
            if not reviews.exists():
                raise Http404("Reviews does not exist")
            return reviews
        return Reviews.objects.all()


def refresh_token(request):
    """Refresh the access token using the refresh token stored in the session."""
    if 'refresh_token' not in request.session:
        return False
    response = requests.post('http://127.0.0.1:8000/api/token/refresh/',
                             json={'refresh': request.session['refresh_token']})
    if response.status_code == 200:
        tokens = response.json()
        request.session['access_token'] = tokens['access']
        return True
    return False


def register_view(request):
    """Render registration page and handle registration form submission."""
    if request.method == 'POST':
        data = {
            'email': request.POST.get('email'),
            'login': request.POST.get('login'),
            'full_name': request.POST.get('full_name'),
            'password': request.POST.get('password')
        }
        response = requests.post('http://127.0.0.1:8000/api/register/', json=data)
        if response.status_code == 201:
            messages.success(request, 'Регистрация успешна! Пожалуйста, войдите.')
            return redirect('login')
        else:
            messages.error(request, response.json().get('detail', 'Ошибка регистрации'))
    return render(request, 'register.html')


def login_view(request):
    """Render login page and handle login form submission."""
    if request.method == 'POST':
        data = {
            'email': request.POST.get('email'),
            'password': request.POST.get('password')
        }
        response = requests.post('http://127.0.0.1:8000/api/login/', json=data)
        if response.status_code == 200:
            tokens = response.json()
            request.session['access_token'] = tokens['access']
            request.session['refresh_token'] = tokens['refresh']
            # Декодируем access_token для получения user_id
            try:
                decoded_token = jwt.decode(tokens['access'], options={"verify_signature": False})
                user_id = decoded_token.get('user_id')
                if user_id is None:
                    messages.error(request, 'Ошибка: user_id не найден в токене.')
                    return render(request, 'login.html')
                request.session['user_id'] = user_id
            except jwt.InvalidTokenError:
                messages.error(request, 'Ошибка декодирования токена.')
                return render(request, 'login.html')
            messages.success(request, 'Вход успешен!')
            return redirect('profile')
        else:
            messages.error(request, 'Неверный email или пароль')
    return render(request, 'login.html')


def logout_view(request):
    """Handle logout by clearing session tokens."""
    if request.method == 'POST':
        if 'access_token' in request.session:
            response = requests.post(
                'http://127.0.0.1:8000/api/logout/',
                headers={'Authorization': f'Bearer {request.session["access_token"]}'}
            )
            if response.status_code == 200:
                messages.success(request, 'Вы успешно вышли.')
            else:
                messages.error(request, 'Ошибка при выходе.')
        request.session.flush()
        return redirect('login')
    return render(request, 'logout.html')


def profile_view(request):
    """Render user profile page."""
    if 'access_token' not in request.session or 'user_id' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session['user_id']
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    response = requests.get(f'http://127.0.0.1:8000/api/user/{user_id}/', headers=headers)

    if response.status_code == 200:
        user = response.json()
        return render(request, 'profile.html', {'user': user})
    else:
        messages.error(request, 'Ошибка загрузки профиля.')
        return redirect('login')


def change_password_view(request):
    """Render change password page and handle password change."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    if request.method == 'POST':
        data = {
            'current_password': request.POST.get('current_password'),
            'new_password': request.POST.get('new_password')
        }
        response = requests.post(
            f'http://127.0.0.1:8000/api/user/{user_id}/change_password/',
            headers=headers,
            json=data
        )
        if response.status_code == 200:
            messages.success(request, 'Пароль успешно изменён.')
            return redirect('profile')
        elif response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            response = requests.post(
                f'http://127.0.0.1:8000/api/user/{user_id}/change_password/',
                headers=headers,
                json=data
            )
            if response.status_code == 200:
                messages.success(request, 'Пароль успешно изменён.')
                return redirect('profile')
        messages.error(request, response.json().get('error', 'Ошибка смены пароля'))

    return render(request, 'change_password.html')


def families_view(request):
    """Render list of user's families."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    response = requests.get(f'http://127.0.0.1:8000/api/families/{user_id}/', headers=headers)

    if response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.get(f'http://127.0.0.1:8000/api/families/{user_id}/', headers=headers)

    if response.status_code == 200:
        families = response.json()
        return render(request, 'families.html', {'families': families})
    else:
        messages.error(request, 'Ошибка загрузки семей.')
        return redirect('login')


def family_members_view(request, family_id):
    """Render list of family members."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    response = requests.get(f'http://127.0.0.1:8000/api/family/{family_id}/members/', headers=headers)

    if response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.get(f'http://127.0.0.1:8000/api/family/{family_id}/members/', headers=headers)

    if response.status_code == 200:
        members = response.json()
        return render(request, 'family_members.html', {'members': members, 'family_id': family_id})
    else:
        messages.error(request, 'Ошибка загрузки участников семьи.')
        return redirect('families')


def create_family_view(request):
    """Render create family page and handle family creation."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    if request.method == 'POST':
        data = {
            'name': request.POST.get('name'),
            'description': request.POST.get('description')
        }
        response = requests.post('http://127.0.0.1:8000/api/family/', headers=headers, json=data)
        if response.status_code == 201:
            messages.success(request, 'Семья успешно создана.')
            return redirect('families')
        elif response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            response = requests.post('http://127.0.0.1:8000/api/family/', headers=headers, json=data)
            if response.status_code == 201:
                messages.success(request, 'Семья успешно создана.')
                return redirect('families')
        messages.error(request, response.json().get('detail', 'Ошибка создания семьи'))

    return render(request, 'create_family.html')


def trips_view(request):
    """Render list of user's trips."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    response = requests.get(f'http://127.0.0.1:8000/api/trips/{user_id}/', headers=headers)

    if response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.get(f'http://127.0.0.1:8000/api/trips/{user_id}/', headers=headers)

    if response.status_code == 200:
        trips = response.json()
        return render(request, 'trips.html', {'trips': trips})
    else:
        messages.error(request, 'Ошибка загрузки поездок.')
        return redirect('login')


def repeat_trip_view(request, trip_id):
    """Handle trip repeat action."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    response = requests.post(f'http://127.0.0.1:8000/api/trip/{trip_id}/repeat/', headers=headers)

    if response.status_code == 201:
        messages.success(request, 'Поездка успешно скопирована.')
        return redirect('trips')
    elif response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.post(f'http://127.0.0.1:8000/api/trip/{trip_id}/repeat/', headers=headers)
        if response.status_code == 201:
            messages.success(request, 'Поездка успешно скопирована.')
            return redirect('trips')
    messages.error(request, response.json().get('error', 'Ошибка копирования поездки'))
    return redirect('trips')


def places_view(request):
    """Render list of places with category filter."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    category = request.GET.get('category', '')
    url = 'http://127.0.0.1:8000/api/places/filter/'
    if category:
        url += f'?category={category}'

    response = requests.get(url, headers=headers)

    if response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.get(url, headers=headers)

    if response.status_code == 200:
        places = response.json()
        return render(request, 'places.html', {'places': places, 'category': category})
    elif response.status_code == 404:
        messages.error(request, 'Места с такой категорией не найдены.')
        return render(request, 'places.html', {'places': [], 'category': category})
    else:
        messages.error(request, 'Ошибка загрузки мест.')
        return redirect('login')


def place_reviews_view(request, place_id):
    """Render reviews for a specific place."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    response = requests.get(f'http://127.0.0.1:8000/api/place/{place_id}/reviews/', headers=headers)

    if response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.get(f'http://127.0.0.1:8000/api/place/{place_id}/reviews/', headers=headers)

    if response.status_code == 200:
        reviews = response.json()
        return render(request, 'place_reviews.html', {'reviews': reviews, 'place_id': place_id})
    else:
        messages.error(request, 'Ошибка загрузки отзывов.')
        return redirect('places')


def reviews_view(request):
    """Render list of reviews with mark filter."""
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    mark = request.GET.get('mark', '')
    url = 'http://127.0.0.1:8000/api/reviews/filter/'
    if mark:
        url += f'?mark={mark}'

    response = requests.get(url, headers=headers)

    if response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.get(url, headers=headers)

    if response.status_code == 200:
        reviews = response.json()
        return render(request, 'reviews.html', {'reviews': reviews, 'mark': mark})
    elif response.status_code == 404:
        messages.error(request, 'Отзывы с такой оценкой не найдены.')
        return render(request, 'reviews.html', {'reviews': [], 'mark': mark})
    else:
        messages.error(request, 'Ошибка загрузки отзывов.')
        return redirect('login')