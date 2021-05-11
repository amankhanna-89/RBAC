import unittest
import rbac
from constant import *


class TestLogin(unittest.TestCase):

    def setUp(self):
        rbac.setup()

    def tearDown(self):
        rbac.clean_up()

    def test_login(self):

        for email, password, username, new_password, error_msg in [
            (admin_email, admin_password, admin_email, None, None),
            (user_email, user_password, user_email, 'userpw', None),
            ('user2@ok.com', 'user2pw', 'user2', 'user2pw2', 'Invalid User Credentials !!!')
        ]:
            password = rsa.encrypt(password.encode(), publicKey)
            if error_msg is None:
                user = rbac.AuthorizedUser.get_user(email, password, new_password)
                self.assertEqual(user.email, username)
            else:
                with self.assertRaises(Exception) as error:
                    rbac.AuthorizedUser.get_user(email, password, new_password)
                self.assertEqual(str(error.exception), error_msg)


class TestUserOperation(unittest.TestCase):

    def setUp(self):
        rbac.setup()

    def tearDown(self):
        rbac.clean_up()

    def test_view_all_users(self):
        rbac.setup()
        self.assertEqual(rbac.User.get_all_users(), [admin_email, user_email])

        rbac.clean_up()

    def test_create_user(self):
        rbac.setup()

        self.assertEqual(rbac.User.get_all_users(), [admin_email, user_email])

        # create_user(cls, username, password, is_staff, email, password_change_required, role_list=[]):
        rbac.User.create_user('user2', 'user2pw', True, 'user2@ok.com', False, [])

        self.assertEqual(rbac.User.get_all_users(), [admin_email, user_email, 'user2@ok.com'])

        rbac.clean_up()

    def test_invalid_create_user(self):
        rbac.setup()

        # create_user(cls, username, password, is_staff, email, password_change_required, role_list=[]):
        with self.assertRaises(Exception) as error:
            rbac.User.create_user('user2', 'user2pw', True, admin_email, False, [])

        self.assertEqual(str(error.exception), "Email already exist, Try again !!!")

        rbac.clean_up()

    def test_delete_user(self):
        rbac.setup()

        self.assertEqual(rbac.User.get_all_users(), [admin_email, user_email])

        rbac.User.delete_user(user_email)
        self.assertEqual(rbac.User.get_all_users(), [admin_email])

        rbac.clean_up()

    def test_invalid_delete_user(self):
        rbac.setup()

        self.assertEqual(rbac.User.get_all_users(), [admin_email, user_email])

        with self.assertRaises(Exception) as error:
            rbac.User.delete_user('user2')

        self.assertEqual(str(error.exception), "User with this email Not Found !!!")

        rbac.clean_up()

    def test_associate_new_role_to_user(self):
        rbac.setup()
        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        #   create_role(cls, rolename, displayname, customer_modifiable, createdby, permission=[]):
        rbac.Role.create_role('custom_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role', 'custom_role'])

        rbac.User.associate_new_role_to_user(user_email, ['custom_role'])

    def test_invalid_associate_new_role_to_user(self):
        rbac.setup()
        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        #   create_role(cls, rolename, displayname, customer_modifiable, createdby, permission=[]):
        rbac.Role.create_role('custom_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role', 'custom_role'])


        with self.assertRaises(Exception) as error:
            rbac.User.associate_new_role_to_user(user_email, ['my_role'])

        self.assertEqual(str(error.exception), "Invalid Role Name my_role!!!")

    def test_delete_role_from_user_role_list(self):
        rbac.setup()
        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        #   create_role(cls, rolename, displayname, customer_modifiable, createdby, permission=[]):
        rbac.Role.create_role('custom_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role', 'custom_role'])

        rbac.User.associate_new_role_to_user(user_email, ['custom_role'])

        user = rbac.User.remove_role_from_user(user_email, ['custom_role'])
        # print(user.role_list)

    def test_invalid_delete_role_from_user_role_list(self):
        rbac.setup()
        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        #   create_role(cls, rolename, displayname, customer_modifiable, createdby, permission=[]):
        rbac.Role.create_role('custom_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role', 'custom_role'])

        rbac.User.associate_new_role_to_user(user_email, ['custom_role'])

        with self.assertRaises(Exception) as error:
            rbac.User.remove_role_from_user(user_email, ['my_role'])

        self.assertEqual(str(error.exception), "Invalid Role Name my_role!!!")


class TestRoleOperation(unittest.TestCase):

    def setUp(self):
        rbac.setup()

    def tearDown(self):
        rbac.clean_up()

    def test_view_all_roles(self):
        rbac.setup()

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        rbac.clean_up()

    def test_create_roles(self):
        rbac.setup()

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        #   create_role(cls, rolename, displayname, customer_modifiable, createdby, permission=[]):
        rbac.Role.create_role('custom_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role', 'custom_role'])

        rbac.clean_up()

    def test_invalid_create_role(self):
        rbac.setup()

        #   create_role(cls, rolename, displayname, customer_modifiable, createdby, permission=[]):
        with self.assertRaises(Exception) as error:
            rbac.Role.create_role('admin_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(str(error.exception), "Role With this name already exist, Try again !!!")

        rbac.clean_up()

    def test_delete_role(self):
        rbac.setup()

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])
        rbac.Role.create_role('custom_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role', 'custom_role'])

        rbac.Role.delete_role('admin_role')
        self.assertEqual(rbac.Role.get_all_roles(), ['custom_role'])

        rbac.clean_up()

    def test_invalid_delete_role(self):
        rbac.setup()

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        with self.assertRaises(Exception) as error:
            rbac.Role.delete_role('staff_role')

        self.assertEqual(str(error.exception), "Role with rolename:staff_role Not Found !!!")

        rbac.clean_up()


class TestResourceOperation(unittest.TestCase):

    def setUp(self):
        rbac.setup()

    def tearDown(self):
        rbac.clean_up()

    def test_view_all_resources(self):
        rbac.setup()

        self.assertEqual(rbac.Resource.get_all_resources(), ['admin_resource'])

        rbac.clean_up()

    def test_create_resource(self):
        rbac.setup()

        self.assertEqual(rbac.Resource.get_all_resources(), ['admin_resource'])

        #  create_resource(cls, resourcename, displayname, resource, customer_modifiable, createdby)
        rbac.Resource.create_resource('my_resource', 'My Resource', '/api/v1/myapi', True, admin_email)

        self.assertEqual(rbac.Resource.get_all_resources(), ['admin_resource', 'my_resource'])

        rbac.clean_up()

    def test_invalid_create_resource(self):
        rbac.setup()

        self.assertEqual(rbac.Resource.get_all_resources(), ['admin_resource'])

        #  create_resource(cls, resourcename, displayname, resource, customer_modifiable, createdby)
        with self.assertRaises(Exception) as error:
            rbac.Resource.create_resource('admin_resource', 'My Resource', '/api/v1/myapi', True, admin_email)

        self.assertEqual(str(error.exception), "Resource With this name already exist, Try again !!!")

        rbac.clean_up()

    def test_delete_resource(self):
        rbac.setup()

        self.assertEqual(rbac.Resource.get_all_resources(), ['admin_resource'])
        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])

        #  create_resource(cls, resourcename, displayname, resource, customer_modifiable, createdby)
        with self.assertRaises(Exception) as error:
            rbac.Resource.create_resource('admin_resource', 'My Resource', '/api/v1/myapi', True, admin_email)

        self.assertEqual(str(error.exception), "Resource With this name already exist, Try again !!!")

        rbac.clean_up()


        rbac.setup()

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])
        rbac.Role.create_role('custom_role', 'Custom Role', True, admin_email, [])

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role', 'custom_role'])

        rbac.Role.delete_role('admin_role')
        self.assertEqual(rbac.Role.get_all_roles(), ['custom_role'])

        rbac.clean_up()

    def test_invalid_delete_role(self):
        rbac.setup()

        self.assertEqual(rbac.Role.get_all_roles(), ['admin_role'])

        with self.assertRaises(Exception) as error:
            rbac.Role.delete_role('staff_role')

        self.assertEqual(str(error.exception), "Role with rolename:staff_role Not Found !!!")

        rbac.clean_up()


class TestPermissionOperation(unittest.TestCase):

    def setUp(self):
        rbac.setup()

    def tearDown(self):
        rbac.clean_up()

    def test_view_all_permissions(self):
        rbac.setup()

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])

        rbac.clean_up()

    def test_create_permission(self):
        rbac.setup()

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])

        #  create_permission(cls, permissionname, displayname, operation_list, resource, createdby):
        rbac.Permission.create_permission('custom_permission', 'Custom Permission', ['GET'], 'admin_resource', admin_email)

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission', 'custom_permission'])

        rbac.clean_up()

    def test_invalid_resource_create_permission(self):
        rbac.setup()

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])

        #  create_permission(cls, permissionname, displayname, operation_list, resource, createdby):
        with self.assertRaises(Exception) as error:
            rbac.Permission.create_permission('custom_permission', 'Custom Permission', ['GET'], 'my_resource', admin_email)

        self.assertEqual(str(error.exception), "Resource With this name do not exist !!!")

        rbac.clean_up()

    def test_invalid_operation_create_permission(self):
        rbac.setup()

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])

        #  create_permission(cls, permissionname, displayname, operation_list, resource, createdby):
        with self.assertRaises(Exception) as error:
            rbac.Permission.create_permission('custom_permission', 'Custom Permission', ['GET', 'PUT'], 'admin_resource', admin_email)

        self.assertEqual(str(error.exception), "Invalid Operation Name PUT!!!")

        rbac.clean_up()

    def test_invalid_create_permission(self):
        rbac.setup()

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])

        #  create_permission(cls, permissionname, displayname, operation_list, resource, createdby):
        with self.assertRaises(Exception) as error:
            rbac.Permission.create_permission('default_permission', 'Custom Permission', ['GET', 'PUT'], 'admin_resource', admin_email)

        self.assertEqual(str(error.exception), "Permission With this name already exist, Try again !!!")

        rbac.clean_up()

    def test_delete_permission(self):
        rbac.setup()

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])
        rbac.Role.delete_permission('default_permission')
        self.assertEqual(rbac.Permission.get_all_permissions(), [])

        rbac.clean_up()

    def test_invalid_delete_permission(self):
        rbac.setup()

        self.assertEqual(rbac.Permission.get_all_permissions(), ['default_permission'])

        with self.assertRaises(Exception) as error:
            rbac.Role.delete_permission('my_permission')

        self.assertEqual(str(error.exception), "Permission with permissionname:my_permission Not Found !!!")

        rbac.clean_up()

    def test_remove_operation_from_permission(self):
        rbac.setup()

        old_permission = rbac.Permission.get_permission('default_permission')

        self.assertEqual(old_permission.operation, ['GET', 'PATCH', 'DELETE', 'POST'])

        permission = rbac.Permission.remove_operation_from_permission('default_permission', ['POST'])

        self.assertEqual(permission.operation, ['GET', 'PATCH', 'DELETE'])
        rbac.clean_up()

    def test_associate_new_operation_to_permission(self):
        rbac.setup()

        old_permission = rbac.Permission.get_permission('default_permission')
        self.assertEqual(old_permission.operation, ['GET', 'PATCH', 'DELETE', 'POST'])

        permission = rbac.Permission.remove_operation_from_permission('default_permission', ['POST'])
        self.assertEqual(permission.operation, ['GET', 'PATCH', 'DELETE'])

        permission = rbac.Permission.associate_new_operation_to_permission('default_permission', ['POST'])
        self.assertEqual(sorted(permission.operation), sorted(['GET', 'DELETE', 'PATCH', 'POST']))

        rbac.clean_up()


# To Run this file as $ python test_rbac.py (in virtual env)
if __name__ == '__main__':
    unittest.main()