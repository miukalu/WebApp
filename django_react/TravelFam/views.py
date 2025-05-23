from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404, render, redirect
from django.http import Http404
import jwt
from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import User, Family, FamilyMember, FamilyRequests, Place, Reviews, Trip, TripPlace
from .serializers import (UserRegistrationSerializer, UserSerializer, FamilySerializer, FamilyMemberSerializer,
                          FamilyRequestSerializer,
                          PlaceSerializer, ReviewSerializer, TripSerializer, UserLogoutSerializer,
                          ChangePasswordSerializer)
import requests


class UserLoginView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]


class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer


class UserLogoutView(generics.GenericAPIView):
    serializer_class = UserLogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        print(f"Received data in UserLogoutView: {request.data}")
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'logged out'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
            return Response({'error': 'Текущий пароль неверный'},
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
            return self.queryset.filter(family_id=family_id, status=FamilyRequests.PENDING)
        return self.queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def accept(self, request, family_id=None, user_id=None):
        if not (request.user.is_superuser or
                FamilyMember.objects.filter(
                    user=request.user,
                    family_id=family_id,
                    role='creator'
                ).exists()):
            return Response(
                {'error': 'You are not a creator of this family'},
                status=status.HTTP_403_FORBIDDEN
            )
        request_obj = get_object_or_404(
            FamilyRequests,
            family_id=family_id,
            user_id=user_id,
            status=FamilyRequests.PENDING
        )
        # Получаем роль из запроса (по умолчанию 'member')
        role = request.data.get('role', 'member').strip().lower()
        # Проверяем, что роль не 'creator'
        if role == 'creator':
            return Response(
                {'error': 'Only the family creator can have the role "creator". Choose a different role.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        request_obj.status = FamilyRequests.ACCEPTED
        request_obj.save()
        # Создаём или обновляем участника семьи с указанной ролью
        member, created = FamilyMember.objects.update_or_create(
            user_id=user_id,
            family_id=family_id,
            defaults={'role': role}
        )
        return Response({'status': 'request accepted', 'role_assigned': role}, status=status.HTTP_200_OK)

    def decline(self, request, family_id=None, user_id=None):
        if not (request.user.is_superuser or
                FamilyMember.objects.filter(
                    user=request.user,
                    family_id=family_id,
                    role='creator'
                ).exists()):
            return Response(
                {'error': 'You are not a creator of this family'},
                status=status.HTTP_403_FORBIDDEN
            )
        request_obj = get_object_or_404(
            FamilyRequests,
            family_id=family_id,
            user_id=user_id,
            status=FamilyRequests.PENDING
        )
        request_obj.status = FamilyRequests.DECLINED
        request_obj.save()
        return Response({'status': 'request declined'}, status=status.HTTP_200_OK)


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
        for trip_place in original_trip.tripplace_set.all():
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
    refresh = request.session.get('refresh_token')
    if not refresh:
        print("No refresh token found in session.")
        return False

    try:
        response = requests.post(
            'http://127.0.0.1:8000/api/token/refresh/',
            json={'refresh': refresh}
        )
        print(f"Refresh Token API response status: {response.status_code}, body: {response.text}")

        if response.status_code == 200:
            data = response.json()
            request.session['access_token'] = data['access']
            print(f"Access token refreshed: {data['access']}")
            return True
        else:
            print("Failed to refresh token.")
            return False
    except requests.RequestException as e:
        print(f"Refresh token request error: {e}")
        return False


def register_view(request):
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
    if request.method == 'POST':
        if 'refresh_token' not in request.session or 'access_token' not in request.session:
            messages.error(request, 'Вы не авторизованы или токены отсутствуют.')
            return redirect('login')
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        data = {'refresh': request.session['refresh_token']}
        try:
            response = requests.post(
                'http://127.0.0.1:8000/api/logout/',
                headers=headers,
                json=data
            )
            print(f"Logout API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 200:
                messages.success(request, 'Вы успешно вышли.')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка при выходе.')
                except ValueError:
                    error_msg = 'Ошибка при выходе: сервер вернул некорректный ответ.'
                messages.error(request, error_msg)
        except requests.RequestException as e:
            print(f"Logout request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу.')
        request.session.flush()
        return redirect('login')
    return render(request, 'logout.html')


def profile_view(request):
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
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')

        if not all([current_password, new_password]):
            messages.error(request, 'Все поля обязательны для заполнения.')
            return render(request, 'change_password.html')

        if current_password == new_password:
            messages.error(request, 'Пароли совпадают.')
            return render(request, 'change_password.html')

        data = {
            'current_password': current_password,
            'new_password': new_password
        }
        endpoint = f'http://127.0.0.1:8000/api/user/{user_id}/change-password/'
        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=data
            )
            print(f"Change Password API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.post(
                    endpoint,
                    headers=headers,
                    json=data
                )
                print(f"Retry Change Password API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 200:
                messages.success(request, 'Пароль успешно изменён.')
                return redirect('profile')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка смены пароля')
                except ValueError:
                    error_msg = 'Ошибка смены пароля: сервер вернул некорректный ответ.'
                messages.error(request, error_msg)
                return render(request, 'change_password.html')

        except requests.RequestException as e:
            print(f"Change Password request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу при смене пароля.')
            return render(request, 'change_password.html')

    return render(request, 'change_password.html')


def update_profile_view(request):
    if 'access_token' not in request.session or 'user_id' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session['user_id']
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    response = requests.get(f'http://127.0.0.1:8000/api/user/{user_id}/', headers=headers)
    if response.status_code != 200:
        if response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            response = requests.get(f'http://127.0.0.1:8000/api/user/{user_id}/', headers=headers)
        if response.status_code != 200:
            messages.error(request, 'Ошибка загрузки данных профиля.')
            return redirect('login')

    user = response.json()

    if request.method == 'POST':
        data = {
            'full_name': request.POST.get('full_name'),
            'login': request.POST.get('login'),
            'preferences': request.POST.get('preferences', '')
        }

        if not data['full_name'] or not data['login']:
            messages.error(request, 'Имя и логин обязательны для заполнения.')
            return render(request, 'update_profile.html', {'user': user})

        try:
            response = requests.put(
                f'http://127.0.0.1:8000/api/user/{user_id}/',
                headers=headers,
                json=data
            )
            print(f"Update Profile API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.put(
                    f'http://127.0.0.1:8000/api/user/{user_id}/',
                    headers=headers,
                    json=data
                )
                print(f"Retry Update Profile API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 200:
                messages.success(request, 'Данные профиля успешно обновлены.')
                return redirect('profile')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка обновления профиля.')
                except ValueError:
                    error_msg = 'Ошибка обновления профиля: сервер вернул некорректный ответ.'
                messages.error(request, error_msg)
                return render(request, 'update_profile.html', {'user': user})

        except requests.RequestException as e:
            print(f"Update Profile request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу при обновлении профиля.')
            return render(request, 'update_profile.html', {'user': user})

    return render(request, 'update_profile.html', {'user': user})


def families_view(request):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    if request.method == 'POST':
        family_id = request.POST.get('family_id', 9)
        data = {
            'user': user_id
        }

        try:
            family_membership_response = requests.get(f'http://127.0.0.1:8000/api/family/{user_id}/', headers=headers)
            print(f"Family Membership API response status: {family_membership_response.status_code}, body: {family_membership_response.text}")

            if family_membership_response.status_code == 200:
                family_memberships = family_membership_response.json()
                family_ids = [family['id'] for family in family_memberships]
                if int(family_id) in family_ids:
                    messages.error(request, 'Вы уже состоите в этой семье.')
                    return redirect('families')
        except requests.RequestException as e:
            print(f"Family Membership request error: {e}")
            messages.error(request, 'Ошибка проверки членства в семье.')
            return redirect('families')

        endpoint = f'http://127.0.0.1:8000/api/family/{family_id}/request/'
        try:
            response = requests.post(endpoint, headers=headers, json=data)
            print(f"Family Request API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.post(endpoint, headers=headers, json=data)
                print(f"Retry Family Request API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 200 or response.status_code == 201:
                messages.success(request, 'Запрос на присоединение к семье отправлен.')
                return redirect('families')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка отправки запроса')
                except ValueError:
                    error_msg = f'Ошибка отправки запроса: сервер вернул статус {response.status_code}.'
                messages.error(request, error_msg)
        except requests.RequestException as e:
            print(f"Family Request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу.')
            return redirect('families')

    try:
        families_response = requests.get(f'http://127.0.0.1:8000/api/family/{user_id}/', headers=headers)
        print(f"Families API response status: {families_response.status_code}, body: {families_response.text}")
        families = families_response.json() if families_response.status_code == 200 else []
        print(f"Families data: {families}")
    except requests.RequestException as e:
        print(f"Families request error: {e}")
        messages.error(request, 'Ошибка загрузки семей.')
        families = []

    return render(request, 'families.html', {'families': families})

def family_members_view(request, family_id):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'remove_member':
            member_id = request.POST.get('member_id')
            try:
                url = f'http://127.0.0.1:8000/api/family/{family_id}/member/{member_id}/'
                response = requests.delete(url, headers=headers)
                print(f"Remove Member API response status: {response.status_code}, body: {response.text}")

                if response.status_code == 401 and refresh_token(request):
                    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                    response = requests.delete(url, headers=headers)
                    print(f"Retry Remove Member API response status: {response.status_code}, body: {response.text}")

                if response.status_code == 204:
                    messages.success(request, 'Участник успешно удалён из семьи.')
                else:
                    try:
                        error_msg = response.json().get('error', 'Ошибка удаления участника.')
                    except ValueError:
                        error_msg = 'Ошибка удаления участника: сервер вернул некорректный ответ.'
                    messages.error(request, error_msg)
            except requests.RequestException as e:
                print(f"Remove Member request error: {e}")
                messages.error(request, 'Ошибка подключения к серверу.')
            return redirect('family-members', family_id=family_id)

        elif action in ['accept_request', 'decline_request']:
            request_user_id = request.POST.get('request_user_id')
            sub_action = 'accept' if action == 'accept_request' else 'decline'
            try:
                url = f'http://127.0.0.1:8000/api/family/{family_id}/request/{request_user_id}/{sub_action}/'
                role = request.POST.get('role', 'member').strip()
                if not role:
                    messages.error(request, 'Пожалуйста, укажите роль.')
                    return redirect('family-members', family_id=family_id)
                data = {'role': role}
                response = requests.post(url, headers=headers, json=data)
                print(f"{sub_action.capitalize()} Request API response status: {response.status_code}, body: {response.text}")
                if response.status_code == 401 and refresh_token(request):
                    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                    response = requests.post(url, headers=headers, json=data)
                    print(f"Retry {sub_action.capitalize()} Request API response status: {response.status_code}, body: {response.text}")
                if response.status_code == 200:
                    messages.success(request, f'Запрос успешно {"принят" if action == "accept_request" else "отклонён"}.')
                else:
                    try:
                        error_msg = response.json().get('error', f'Ошибка {"принятия" if action == "accept_request" else "отклонения"} запроса.')
                    except ValueError:
                        error_msg = f'Ошибка {"принятия" if action == "accept_request" else "отклонения"} запроса: сервер вернул некорректный ответ.'
                    messages.error(request, error_msg)
            except requests.RequestException as e:
                print(f"{sub_action.capitalize()} Request error: {e}")
                messages.error(request, 'Ошибка подключения к серверу.')
            return redirect('family-members', family_id=family_id)

    try:
        members_response = requests.get(f'http://127.0.0.1:8000/api/family/{family_id}/members/', headers=headers)
        print(f"Members API response status: {members_response.status_code}, body: {members_response.text}")

        if members_response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            members_response = requests.get(f'http://127.0.0.1:8000/api/family/{family_id}/members/', headers=headers)
            print(f"Retry Members API response status: {members_response.status_code}, body: {members_response.text}")

        if members_response.status_code != 200:
            messages.error(request, 'Ошибка загрузки участников семьи.')
            return redirect('families')

        members = members_response.json()

        for member in members:
            user_id = member['user']  # user — это ID
            user_response = requests.get(f'http://127.0.0.1:8000/api/user/{user_id}/', headers=headers)
            print(f"User API response for user_id {user_id}: status: {user_response.status_code}, body: {user_response.text}")
            if user_response.status_code == 200:
                member['user'] = user_response.json()  # Заменяем ID на данные пользователя
            else:
                member['user'] = {'id': user_id, 'login': 'Неизвестный', 'full_name': 'Неизвестный'}

        user_id = request.session.get('user_id', 1)
        user_role = None
        for member in members:
            if str(member['user']['id']) == str(user_id):
                user_role = member['role']
                break
        print(f"Current user role: {user_role}")

        requests_response = requests.get(f'http://127.0.0.1:8000/api/family/{family_id}/requests/', headers=headers)
        print(f"Requests API response status: {requests_response.status_code}, body: {requests_response.text}")

        if requests_response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            requests_response = requests.get(f'http://127.0.0.1:8000/api/family/{family_id}/requests/', headers=headers)
            print(f"Retry Requests API response status: {requests_response.status_code}, body: {requests_response.text}")

        requests_data = requests_response.json() if requests_response.status_code == 200 else []

        for req in requests_data:
            user_id = req['user']  # user — это ID
            user_response = requests.get(f'http://127.0.0.1:8000/api/user/{user_id}/', headers=headers)
            print(f"User API response for request user_id {user_id}: status: {user_response.status_code}, body: {user_response.text}")
            if user_response.status_code == 200:
                req['user'] = user_response.json()  # Заменяем ID на данные пользователя
            else:
                req['user'] = {'id': user_id, 'login': 'Неизвестный', 'full_name': 'Неизвестный'}

    except requests.RequestException as e:
        print(f"Family Members/Requests request error: {e}")
        messages.error(request, 'Ошибка загрузки данных.')
        return redirect('families')

    return render(request, 'family_members.html', {
        'members': members,
        'requests': requests_data,
        'family_id': family_id,
        'user_role': user_role
    })


def create_family_view(request):
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


def create_trip_view(request):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    try:
        families_response = requests.get(f'http://127.0.0.1:8000/api/family/{user_id}/', headers=headers)
        print(f"Families API response status: {families_response.status_code}, body: {families_response.text}")

        if families_response.status_code != 200:
            messages.error(request,
                           f'Ошибка загрузки семей: статус {families_response.status_code}. Возможно, у вас нет семей.')
            return redirect('create-family')

        try:
            families_data = families_response.json()
            families = families_data if isinstance(families_data, list) else families_data.get('results', [])
        except ValueError as e:
            print(f"JSON decode error: {e}")
            messages.error(request, 'Ошибка обработки данных семей. Пожалуйста, попробуйте позже.')
            return redirect('create-family')

        if not families:
            messages.warning(request, 'У вас нет доступных семей. Создайте семью сначала.')
            return redirect('create-family')

    except requests.RequestException as e:
        print(f"Request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу семей. Пожалуйста, попробуйте позже.')
        return redirect('create-family')

    if request.method == 'POST':
        try:
            family_id = int(request.POST.get('family'))
        except (ValueError, TypeError):
            messages.error(request, 'Неверный идентификатор семьи.')
            return render(request, 'create_trip.html', {'families': families})

        trip_data = {
            'name': request.POST.get('name'),
            'country': request.POST.get('country'),
            'city': request.POST.get('city'),
            'start_date': request.POST.get('start_date'),
            'end_date': request.POST.get('end_date', None),
            'family': family_id,
            'status': request.POST.get('status', 'planned'),
        }
        print(f"Sending trip data: {trip_data}")

        required_fields = ['name', 'country', 'city', 'start_date']
        for field in required_fields:
            if not trip_data[field]:
                messages.error(request, f'Поле "{field}" обязательно для заполнения.')
                return render(request, 'create_trip.html', {'families': families})

        endpoint = 'http://127.0.0.1:8000/trip/'
        try:
            response = requests.post(
                endpoint,
                json=trip_data,
                headers=headers
            )
            print(f"Create Trip API response status for {endpoint}: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.post(
                    endpoint,
                    json=trip_data,
                    headers=headers
                )
                print(
                    f"Retry Create Trip API response status for {endpoint}: {response.status_code}, body: {response.text}")

            if response.status_code == 201:
                messages.success(request, 'Поездка успешно создана.')
                return redirect('trips')
            elif response.status_code == 400:
                error_detail = response.json().get('detail', response.json())
                messages.error(request, f'Ошибка создания поездки: {error_detail}')
            elif response.status_code == 404:
                messages.error(request,
                               f'Эндпоинт для создания поездки не найден ({endpoint}). Проверьте конфигурацию API.')
            else:
                messages.error(request, f'Ошибка сервера при создании поездки: {response.status_code}')

            return render(request, 'create_trip.html', {'families': families})

        except requests.RequestException as e:
            print(f"Create Trip request error for {endpoint}: {e}")
            messages.error(request, f'Ошибка подключения к серверу при создании поездки ({endpoint}).')
            return render(request, 'create_trip.html', {'families': families})

    return render(request, 'create_trip.html', {'families': families})


def trips_view(request):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    try:
        families_response = requests.get(f'http://127.0.0.1:8000/api/family/{user_id}/', headers=headers)
        print(f"Families API response status: {families_response.status_code}, body: {families_response.text}")
        families = families_response.json() if families_response.status_code == 200 else []
        family_names = {family['id']: family['name'] for family in families}
    except requests.RequestException as e:
        print(f"Families request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу семей.')
        families = []
        family_names = {}

    family_members = []
    for family in families:
        try:
            family_id = family['id']
            members_response = requests.get(f'http://127.0.0.1:8000/api/family/{family_id}/members/', headers=headers)
            print(
                f"Family Members API response status for family {family_id}: {members_response.status_code}, body: {members_response.text}")
            if members_response.status_code == 200:
                members = members_response.json()
                family_members.extend(members)
        except requests.RequestException as e:
            print(f"Family Members request error for family {family_id}: {e}")
            messages.warning(request, f'Ошибка загрузки членов семьи {family.get("name", "Неизвестная семья")}.')

    try:
        response = requests.get(f'http://127.0.0.1:8000/api/trips/{user_id}/', headers=headers)
        print(f"Trips API response status: {response.status_code}, body: {response.text}")

        if response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            response = requests.get(f'http://127.0.0.1:8000/api/trips/{user_id}/', headers=headers)
            print(f"Retry Trips API response status: {response.status_code}, body: {response.text}")

        context = {'families': families, 'family_members': family_members}
        if response.status_code == 200:
            trips = response.json()
            print(f"Trips data: {trips}")
            for trip in trips:
                family_id = trip.get('family') if isinstance(trip.get('family'), int) else trip.get('family', {}).get(
                    'id')
                trip['family_name'] = family_names.get(family_id, 'Неизвестная семья')
            context['trips'] = trips
            return render(request, 'trips.html', context)
        elif response.status_code == 404:
            messages.warning(request, 'У вас пока нет поездок.')
            context['trips'] = []
            return render(request, 'trips.html', context)
        else:
            messages.error(request, f'Ошибка загрузки поездок: {response.text}')
            return redirect('login')

    except requests.RequestException as e:
        print(f"Trips request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу поездок.')
        return redirect('login')

def trip_details_view(request, trip_id):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    user_id = request.session.get('user_id', 1)
    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    try:
        families_response = requests.get(f'http://127.0.0.1:8000/api/family/{user_id}/', headers=headers)
        print(f"Families API response status: {families_response.status_code}, body: {families_response.text}")
        families = families_response.json() if families_response.status_code == 200 else []
        family_names = {family['id']: family['name'] for family in families}
    except requests.RequestException as e:
        print(f"Families request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу семей.')
        family_names = {}

    if request.method == 'POST':
        new_status = request.POST.get('status')
        if new_status not in ['planned', 'in_progress', 'completed']:
            messages.error(request, 'Недопустимый статус.')
            return redirect('trip-details', trip_id=trip_id)

        try:
            url = f'http://127.0.0.1:8000/trip/{trip_id}/'
            response = requests.patch(url, headers=headers, json={'status': new_status})
            print(f"Update Trip Status API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.patch(url, headers=headers, json={'status': new_status})
                print(f"Retry Update Trip Status API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 200:
                messages.success(request, 'Статус поездки успешно изменён.')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка изменения статуса.')
                except ValueError:
                    error_msg = f'Ошибка изменения статуса: сервер вернул статус {response.status_code}.'
                messages.error(request, error_msg)
        except requests.RequestException as e:
            print(f"Update Trip Status request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу при изменении статуса.')
        return redirect('trip-details', trip_id=trip_id)

    try:
        trip_response = requests.get(f'http://127.0.0.1:8000/trip/{trip_id}/', headers=headers)
        print(f"Trip Details API response status: {trip_response.status_code}, body: {trip_response.text}")

        if trip_response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            trip_response = requests.get(f'http://127.0.0.1:8000/trip/{trip_id}/', headers=headers)
            print(f"Retry Trip Details API response status: {trip_response.status_code}, body: {trip_response.text}")

        if trip_response.status_code != 200:
            messages.error(request, 'Ошибка загрузки данных поездки.')
            return redirect('trips')

        trip = trip_response.json()

        family_id = trip.get('family') if isinstance(trip.get('family'), int) else trip.get('family', {}).get('id')
        family_name = family_names.get(family_id, 'Неизвестная семья')
        trip['family_name'] = family_name  # Добавляем family_name в trip для шаблона

        places_response = requests.get(f'http://127.0.0.1:8000/trip/{trip_id}/places/', headers=headers)
        places = places_response.json() if places_response.status_code == 200 else []

        available_places_response = requests.get('http://127.0.0.1:8000/api/places/', headers=headers)
        available_places = available_places_response.json() if available_places_response.status_code == 200 else []

    except requests.RequestException as e:
        print(f"Trip Details request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу.')
        return redirect('trips')

    return render(request, 'trip_details.html', {
        'trip': trip,
        'places': places,
        'available_places': available_places,
        'family_name': family_name
    })

def trip_add_place_view(request, trip_id):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    if request.method != 'POST':
        messages.error(request, 'Недопустимый метод запроса.')
        return redirect('trip-details', trip_id=trip_id)

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    place_id = request.POST.get('place_id')

    if not place_id:
        messages.error(request, 'Необходимо выбрать место.')
        return redirect('trip-details', trip_id=trip_id)

    try:
        response = requests.post(
            f'http://127.0.0.1:8000/api/trip/{trip_id}/add_place/',
            headers=headers,
            json={'place_id': place_id}
        )
        print(f"Add Place API response status: {response.status_code}, body: {response.text}")

        if response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            response = requests.post(
                f'http://127.0.0.1:8000/api/trip/{trip_id}/add_place/',
                headers=headers,
                json={'place_id': place_id}
            )
            print(f"Retry Add Place API response status: {response.status_code}, body: {response.text}")

        if response.status_code == 201:
            messages.success(request, 'Место успешно добавлено.')
        else:
            try:
                error_msg = response.json().get('error', 'Ошибка добавления места.')
            except ValueError:
                error_msg = 'Ошибка добавления места: сервер вернул некорректный ответ.'
            messages.error(request, error_msg)

    except requests.RequestException as e:
        print(f"Add Place request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу при добавлении места.')

    return redirect('trip-details', trip_id=trip_id)

def trip_remove_place_view(request, trip_id, place_id):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    if request.method != 'POST':
        messages.error(request, 'Недопустимый метод запроса.')
        return redirect('trip-details', trip_id=trip_id)

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    try:
        response = requests.delete(
            f'http://127.0.0.1:8000/api/trip/{trip_id}/remove_place/',
            headers=headers,
            json={'place_id': place_id}
        )
        print(f"Remove Place API response status: {response.status_code}, body: {response.text}")

        if response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            response = requests.delete(
                f'http://127.0.0.1:8000/api/trip/{trip_id}/remove_place/',
                headers=headers,
                json={'place_id': place_id}
            )
            print(f"Retry Remove Place API response status: {response.status_code}, body: {response.text}")

        if response.status_code == 204:
            messages.success(request, 'Место успешно удалено.')
        else:
            try:
                error_msg = response.json().get('error', 'Ошибка удаления места.')
            except ValueError:
                error_msg = 'Ошибка удаления места: сервер вернул некорректный ответ.'
            messages.error(request, error_msg)

    except requests.RequestException as e:
        print(f"Remove Place request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу при удалении места.')

    return redirect('trip-details', trip_id=trip_id)

def repeat_trip_custom_view(request, trip_id):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    if 'families' not in request.session or not request.session['families']:
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                messages.error(request, 'Не удалось определить пользователя.')
                return redirect('login')

            families_response = requests.get(f'http://127.0.0.1:8000/api/family/{user_id}/', headers=headers)
            print(f"Families API response status: {families_response.status_code}, body: {families_response.text}")

            if families_response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                families_response = requests.get(f'http://127.0.0.1:8000/api/family/{user_id}/', headers=headers)
                print(f"Retry Families API response status: {families_response.status_code}, body: {families_response.text}")

            if families_response.status_code != 200:
                messages.error(request, 'Ошибка загрузки списка семей.')
                request.session['families'] = []
            else:
                request.session['families'] = families_response.json()
                print(f"Families loaded into session: {request.session['families']}")
        except requests.RequestException as e:
            print(f"Families request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу семей.')
            request.session['families'] = []

    try:
        response = requests.get(f'http://127.0.0.1:8000/api/trip/{trip_id}/', headers=headers)
        print(f"Trip API response status: {response.status_code}, body: {response.text}")

        if response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            response = requests.get(f'http://127.0.0.1:8000/api/trip/{trip_id}/', headers=headers)
            print(f"Retry Trip API response status: {response.status_code}, body: {response.text}")

        if response.status_code != 200:
            messages.error(request, 'Ошибка загрузки данных поездки.')
            return redirect('trips')

        trip = response.json()
        family_names = {family['id']: family['name'] for family in request.session.get('families', [])}
        trip['family_name'] = family_names.get(trip.get('family'), 'Неизвестная семья')
    except requests.RequestException as e:
        print(f"Trip request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу.')
        return redirect('trips')

    if request.method == 'POST':
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')

        if not start_date:
            messages.error(request, 'Дата начала обязательна.')
            return render(request, 'repeat_trip.html', {'trip': trip})

        data = {
            'start_date': start_date,
            'end_date': end_date if end_date else None
        }

        try:
            response = requests.post(
                f'http://127.0.0.1:8000/api/trip/{trip_id}/repeat/',
                headers=headers,
                json=data
            )
            print(f"Repeat Trip API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.post(
                    f'http://127.0.0.1:8000/api/trip/{trip_id}/repeat/',
                    headers=headers,
                    json=data
                )
                print(f"Retry Repeat Trip API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 201:
                messages.success(request, 'Поездка успешно скопирована.')
                return redirect('trips')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка копирования поездки.')
                except ValueError:
                    error_msg = 'Ошибка копирования поездки: сервер вернул некорректный ответ.'
                messages.error(request, error_msg)
                return render(request, 'repeat_trip.html', {'trip': trip})

        except requests.RequestException as e:
            print(f"Repeat Trip request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу при копировании поездки.')
            return render(request, 'repeat_trip.html', {'trip': trip})

    return render(request, 'repeat_trip.html', {'trip': trip})

def delete_trip_view(request, trip_id):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    trip = get_object_or_404(Trip, id=trip_id)

    if request.method == 'POST':
        try:
            url = f'http://127.0.0.1:8000/trip/{trip_id}/'
            response = requests.delete(url, headers=headers)
            print(f"Delete Trip API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.delete(url, headers=headers)
                print(f"Retry Delete Trip API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 204:
                messages.success(request, 'Поездка успешно удалена.')
                return redirect('trips')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка удаления поездки.')
                except ValueError:
                    error_msg = f'Ошибка удаления поездки: сервер вернул статус {response.status_code}.'
                messages.error(request, error_msg)
                print(f"Error details: {response.text}")
        except requests.RequestException as e:
            print(f"Delete Trip request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу при удалении поездки.')
        return redirect('trip-details', trip_id=trip_id)
    return redirect('trip-details', trip_id=trip_id)

def places_view(request):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    category = request.GET.get('category', '')
    url = 'http://127.0.0.1:8000/api/places/filter/'
    if category: url += f'?category={category}'

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
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
    response = requests.get(f'http://127.0.0.1:8000/api/place/{place_id}/reviews/', headers=headers)
    print(f"Place Reviews API response status: {response.status_code}, body: {response.text}")

    if response.status_code == 401 and refresh_token(request):
        headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
        response = requests.get(f'http://127.0.0.1:8000/api/place/{place_id}/reviews/', headers=headers)
        print(f"Retry Place Reviews API response status: {response.status_code}, body: {response.text}")

    if response.status_code == 200:
        reviews = response.json()
        return render(request, 'place_reviews.html', {'reviews': reviews, 'place_id': place_id})
    else:
        messages.error(request, 'Ошибка загрузки отзывов.')
        return redirect('places')


def reviews_view(request):
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


def create_review_view(request):
    if 'access_token' not in request.session:
        messages.error(request, 'Пожалуйста, войдите в систему.')
        return redirect('login')

    headers = {'Authorization': f'Bearer {request.session["access_token"]}'}

    try:
        places_response = requests.get('http://127.0.0.1:8000/api/places/', headers=headers)
        print(f"Places API response status: {places_response.status_code}, body: {places_response.text}")

        if places_response.status_code == 401 and refresh_token(request):
            headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
            places_response = requests.get('http://127.0.0.1:8000/api/places/', headers=headers)
            print(f"Retry Places API response status: {places_response.status_code}, body: {places_response.text}")

        if places_response.status_code != 200:
            messages.error(request, 'Ошибка загрузки списка мест.')
            return redirect('reviews')

        places = places_response.json()
    except requests.RequestException as e:
        print(f"Places request error: {e}")
        messages.error(request, 'Ошибка подключения к серверу мест.')
        return redirect('reviews')

    if request.method == 'POST':
        place_id = request.POST.get('place')
        mark = request.POST.get('mark')
        text = request.POST.get('text')

        # Проверяем, что все поля заполнены
        if not all([place_id, mark, text]):
            messages.error(request, 'Все поля обязательны для заполнения.')
            return render(request, 'create_review.html', {'places': places})

        try:
            mark = int(mark)
            if mark < 1 or mark > 5:
                raise ValueError
        except ValueError:
            messages.error(request, 'Оценка должна быть числом от 1 до 5.')
            return render(request, 'create_review.html', {'places': places})

        user_id = request.session.get('user_id')
        if not user_id:
            messages.error(request, 'Ошибка: пользователь не найден в сессии.')
            return redirect('login')

        review_data = {
            'user': user_id,
            'place': place_id,
            'mark': mark,
            'text': text
        }

        try:
            response = requests.post(
                f'http://127.0.0.1:8000/api/place/{place_id}/reviews/',
                headers=headers,
                json=review_data
            )
            print(f"Create Review API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 401 and refresh_token(request):
                headers = {'Authorization': f'Bearer {request.session["access_token"]}'}
                response = requests.post(
                    f'http://127.0.0.1:8000/api/place/{place_id}/reviews/',
                    headers=headers,
                    json=review_data
                )
                print(f"Retry Create Review API response status: {response.status_code}, body: {response.text}")

            if response.status_code == 201:
                messages.success(request, 'Отзыв успешно создан.')
                return redirect('reviews')
            else:
                try:
                    error_msg = response.json().get('error', 'Ошибка создания отзыва.')
                except ValueError:
                    error_msg = 'Ошибка создания отзыва: сервер вернул некорректный ответ.'
                messages.error(request, error_msg)
                return render(request, 'create_review.html', {'places': places})

        except requests.RequestException as e:
            print(f"Create Review request error: {e}")
            messages.error(request, 'Ошибка подключения к серверу при создании отзыва.')
            return render(request, 'create_review.html', {'places': places})

    return render(request, 'create_review.html', {'places': places})