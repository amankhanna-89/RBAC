#::TODO Work Items
# 1) Create a class User which performs all user related operation
# - Creating user
# - validating user
# - resetting password
# - Showing user menu
# - Associating user with role
# - Displaying current roles
# - Displaying current resources
# - Default admin creds will be admin@bluestacks.com/adminpw
# - Admin is having default "create user" role for creating new user
# - Any new user created will not able to create other user unless role is assigned
# - remove role
# - remove user

# 2) Create a class AuthorizedUser which ask for user creds
# - Creds will be authorized with cached userdata

# 3) Create a class role which perform all role related operation
# - create new role
# - display roles associated with user
# - display resources associated with role
# - add resource to a role
# - remove resource from a role
# - delete role
# -
# 4) Create a class resources that is linked with role
# 5) user --can have-> multiple roles , role --can have--> multiple resources
# 6) Each resource can have CRUD actions associated with it

# user -> role -> permission -> resource
# user contain role list
# role contain permission list
# permission contain resource element

#::TODO WorkFlow
# 1) User Log-in with email and password
# 2) Menu shows up with
#   a) create user ( valid for staff user )
#   b) update user role access ( valid for staff user )
#   c) View all roles ( valid for staff user )
#   d) View all resources ( valid for staff user )
#   e) Delete user ( valid for staff user )
#   e) View assigned roles
#   f) View assigned resources
#   g) log out


# Hard Delete
# To Delete a resource
#   a) remove resource from ResourceDict
#   b) remove permissions associated with this resource from PermissionDict
#   c) remove permission associated with this resource from RoleDict-->permission_list

# To Delete a permission
#   a) remove permission from PermissionDict
#   b) remove permission from RoleDict-->permission_list

# To Delete a role
# a) remove role from RoleDict
# b) remove role from UserDict-->role_list

# To Delete a user
# a) remove user from UserDict



from collections import namedtuple
from constant import admin_email, admin_password, user_email, user_password, privateKey, publicKey
import getpass
import rsa


ResourceData = namedtuple('ResourceData', ' resourcename displayname customer_modifiable resource createdby') # resourcename is unique
PermissionData = namedtuple('PermissionData', 'permissionname displayname operation resource createdby') # permissionname is unique
RoleData = namedtuple('RoleData', 'rolename displayname customerModifiable createdby, permission_list') # rolename is unique
UserData = namedtuple('UserData', 'username password is_staff email password_change_required role_list') # email is unique

ResourceDict = {}
PermissionDict = {}
RoleDict = {}
UserDict = {}


class Resource(object):

    @classmethod
    def is_resource_present(cls, resourcename):
        return resourcename in ResourceDict.keys()

    @classmethod
    def validate_resource(cls, resourcename):
        return resourcename not in ResourceDict.keys()

    @classmethod
    def get_all_resources(cls):
        return [k for k in ResourceDict.keys()]

    @classmethod
    def create_resource(cls, resourcename, displayname, resource, customer_modifiable, createdby):
        if resourcename in ResourceDict.keys():
            raise Exception("Resource With this name already exist, Try again !!!")
        ResourceDict[resourcename] = ResourceData(resourcename, displayname, customer_modifiable, resource, createdby)

    @classmethod
    def delete_resource(cls, resourcename):

        if resourcename in ResourceDict.keys():
            del ResourceDict[resourcename]
        else:
            raise Exception("Resource with resourcename:{} Not Found !!!".format(resourcename))
        return resourcename


class Permission(object):
    Operations = ['GET', 'PATCH', 'DELETE', 'POST']

    @classmethod
    def is_permission_present(cls, permissionname):
        return permissionname in PermissionDict.keys()

    @classmethod
    def get_all_permissions(cls):
        return [k for k in PermissionDict.keys()]

    @classmethod
    def view_all_permission(cls):
        print("Available Permission are:")
        for p in PermissionDict.values():
            print("permissionname:{}, displayname:{}, operation:{}, resource:{}".format(
                p.permissionname, p.displayname, p.operation, p.resource))
        return

    @classmethod
    def create_permission(cls, permissionname, displayname, operation_list, resource, createdby):

        if permissionname in PermissionDict.keys():
            raise Exception("Permission With this name already exist, Try again !!!")

        if not Resource.is_resource_present(resource):
            raise Exception("Resource With this name do not exist !!!")

        new_op_list = []
        for operation in operation_list:
            if operation.upper() not in cls.Operations:
                raise Exception("Invalid Operation Name {}!!!".format(operation))
            else:
                new_op_list.append(operation.upper())
        PermissionDict[permissionname] = PermissionData(permissionname, displayname, new_op_list, resource, createdby)

    @classmethod
    def delete_permission(cls, permissionname):

        if permissionname in PermissionDict.keys():
            del PermissionDict[permissionname]
        else:
            raise Exception("Permission with permissionname:{} Not Found !!!".format(permissionname))
        return permissionname

    @classmethod
    def delete_permission_with_resourcename(cls, resourcename):
        permission_list = []
        for permission in PermissionDict.values():
            if resourcename == permission.resource:
                permission_list.append(permission.permissionname)

        for permission in permission_list:
            del PermissionDict[permission]
        return permission_list

    @classmethod
    def get_permission(cls, permissionname):
        if permissionname in PermissionDict.keys():
            permission = PermissionDict[permissionname]
        else:
            raise Exception("Invalid Permission name {}!!!".format(permissionname))
        return permission

    @classmethod
    def associate_new_operation_to_permission(cls, permissionname, operation_list):
        if permissionname in PermissionDict.keys():
            permission = PermissionDict[permissionname]

            permission_operation_list = permission.operation
            for operation in operation_list:
                if operation.upper() not in cls.Operations:
                    raise Exception("Invalid Operation Name {}!!!".format(operation))
                else:
                    permission_operation_list.append(operation.upper())

            permission_operation_list = list(set(permission_operation_list))
            PermissionDict[permissionname] = PermissionData(permission.permissionname, permission.displayname,
                                                            permission_operation_list, permission.resource,
                                                            permission.createdby)
        return PermissionDict[permissionname]

    @classmethod
    def remove_operation_from_permission(cls, permissionname, operation_list):

        if permissionname in PermissionDict.keys():
            permission = PermissionDict[permissionname]

            permission_operation_list = permission.operation
            for operation in operation_list:
                if operation not in cls.Operations:
                    raise Exception("Invalid Operation Name {}!!!".format(operation))
                else:
                    if operation in permission_operation_list:
                        permission_operation_list.remove(operation)

            PermissionDict[permissionname] = PermissionData(permission.permissionname, permission.displayname,
                                                            permission_operation_list, permission.resource,
                                                            permission.createdby)
        return PermissionDict[permissionname]


class Role(object):

    @classmethod
    def validate_role(cls, rolename):
        return rolename not in RoleDict.keys()

    @classmethod
    def is_role_present(cls, rolename):
        return rolename in RoleDict.keys()

    @classmethod
    def create_role(cls, rolename, displayname, customer_modifiable, createdby, permission=[]):
        if rolename in RoleDict.keys():
            raise Exception("Role With this name already exist, Try again !!!")
        RoleDict[rolename] = RoleData(rolename, displayname, customer_modifiable, createdby, permission)

    @classmethod
    def get_all_roles(cls):
        return [k for k in RoleDict.keys()]

    @classmethod
    def delete_role(cls, rolename):
        if rolename in RoleDict.keys():
            role = RoleDict[rolename]
            del RoleDict[rolename]
        else:
            raise Exception("Role with rolename:{} Not Found !!!".format(rolename))
        return role

    @classmethod
    def delete_role_with_permission_list(cls, permission_list):

        for role in RoleDict.values():
            role_permission_list = role.permission_list
            new_permission_list = []
            is_updated = False
            for permission in role_permission_list:
                if permission in permission_list:
                    # print("Removing permission: {} from role:{}".format(permission, role.rolename))
                    is_updated = True
                    continue
                new_permission_list.append(permission)
            if is_updated:
                RoleDict[role.rolename] = RoleData(role.rolename, role.displayname, role.customerModifiable, role.createdby, new_permission_list)

    @classmethod
    def delete_resource(cls, resourcename):
        resourcename = Resource.delete_resource(resourcename)
        if resourcename is None:
            return
        permission_list = Permission.delete_permission_with_resourcename(resourcename)
        cls.delete_role_with_permission_list(permission_list)

    @classmethod
    def delete_permission(cls, permissionname):
        permissionname = Permission.delete_permission(permissionname)

        if permissionname is None:
            return

        cls.delete_role_with_permission_list(list(permissionname))


    @classmethod
    def view_all_roles(cls):
        print("Available Roles are:")
        for r in RoleDict.values():
            print("rolename:{}, permission_list:{}".format(r.rolename, r.permission_list))
        return

    @classmethod
    def associate_new_permission_to_role(cls, rolename, permission_list):

        if rolename in RoleDict.keys():
            role = RoleDict[rolename]
            role_permission_list = role.permission_list
            for permission in permission_list:
                if not Permission.is_permission_present(permission):
                    raise Exception("Invalid Permission Name {}!!!".format(permission))
                else:
                    role_permission_list.append(permission)
            RoleDict[rolename] = RoleData(role.rolename, role.displayname, role.customerModifiable, role.createdby, role_permission_list)
        return RoleDict[rolename]

    @classmethod
    def remove_permission_from_role(cls, rolename, permission_list):

        if rolename in RoleDict.keys():
            role = RoleDict[rolename]
            role_permission_list = role.permission_list
            for permission in permission_list:
                if not Permission.is_permission_present(permission):
                    raise Exception("Invalid Permission Name {}!!!".format(permission))
                else:
                    if permission in role_permission_list:
                        role_permission_list.remove(permission)
            RoleDict[rolename] = RoleData(role.rolename, role.displayname, role.customerModifiable, role.createdby, role_permission_list)
        return RoleDict[rolename]


class User(object):

    @classmethod
    def validate(cls, email):
        return email not in UserDict.keys()

    @classmethod
    def validate_user_creds(cls, email, password):
        user = None
        if email in UserDict.keys():
            userdata = UserDict[email]
            if rsa.decrypt(password, privateKey).decode() == rsa.decrypt(userdata.password, privateKey).decode():
                user = userdata
        return user

    @classmethod
    def create_user(cls, username, password, is_staff, email, password_change_required, role_list=[]):
        if email in UserDict.keys():
            raise Exception("Email already exist, Try again !!!")
        UserDict[email] = UserData(username, password, is_staff, email, password_change_required, role_list)
        return UserDict[email]

    @classmethod
    def delete_user(cls, email):

        if email in UserDict.keys():
            user = UserDict[email]
            del UserDict[email]
        else:
            raise Exception("User with this email Not Found !!!")
        return user

    @classmethod
    def get_all_users(cls):
        return [k for k in UserDict.keys()]

    @classmethod
    def associate_new_role_to_user(cls, email, role_list):

        if email in UserDict.keys():
            user = UserDict[email]
            user_role_list = user.role_list
            for role in role_list:
                if not Role.is_role_present(role):
                    raise Exception("Invalid Role Name {}!!!".format(role))
                else:
                    user_role_list.append(role)
            UserDict[email] = UserData(user.username, user.password, user.is_staff, user.email,
                                       user.password_change_required, list(set(user_role_list)))
        return UserDict[email]

    @classmethod
    def delete_role_from_user_role_list(cls, rolename):
        for user in UserDict.values():
            user_role_list = user.role_list
            new_role_list = []

            is_updated = False
            if rolename in user_role_list:
                print("Removing Role: {} from user:{}".format(rolename, user.username))
                is_updated = True
                continue
            new_role_list.append(rolename)
            if is_updated:
                UserDict[user.email] = UserData(user.username, user.password, user.is_staff, user.email,
                                           user.password_change_required, new_role_list)
        return

    @classmethod
    def delete_role(cls):
        rolename = Role.delete_role()

        if rolename is None:
            return

        cls.delete_role_from_user_role_list(rolename)
        return

    @classmethod
    def remove_role_from_user(cls, email, role_list):
        if email in UserDict.keys():
            user = UserDict[email]
            user_role_list = user.role_list
            for role in role_list:
                if not Role.is_role_present(role):
                    raise Exception("Invalid Role Name {}!!!".format(role))
                else:
                    if role in user_role_list:
                        user_role_list.remove(role)
            UserDict[email] = UserData(user.username, user.password, user.is_staff, user.email, user.password_change_required, user_role_list)
        return UserDict[email]

    @classmethod
    def view_assigned_roles(cls, user):
        print(
            "Email: {} -> Username: {}  is_staff:{} roles: {}!!!".format(user.email, user.username, user.is_staff, user.role_list))
        return

    @classmethod
    def view_assigned_resources(cls, user):
        return

    @classmethod
    def change_password(cls, user, new_password):
        UserDict[user.email] = UserData(user.username, new_password, user.is_staff, user.email, False, user.role_list)
        return


class AuthorizedUser:

    @classmethod
    def get_user(cls,email, password, new_password=None):
        user = User.validate_user_creds(email, password)
        if user is None:
            raise Exception("Invalid User Credentials !!!")
        elif user.password_change_required:
            User.change_password(user, new_password)
        return user

    @classmethod
    def menu(cls, user):
        index = 1
        print("\t\t\tMENU\t\t\t")
        if user.is_staff:
            print("{}: Create New User".format(index))
            index += 1
            print("{}: Delete User".format(index))
            index += 1
            print("{}: Show All Users".format(index))
            index += 1
            print("{}: Associate new Role to user".format(index))
            index += 1
            print("{}: Remove Existing Role from user".format(index))
            index += 1

            print("{}: Create New Role".format(index))
            index += 1
            print("{}: Delete Existing Role".format(index))
            index += 1
            print("{}: Show All Roles".format(index))
            index += 1
            print("{}: Associate new Permission to role".format(index))
            index += 1
            print("{}: Remove Existing Permission from role".format(index))
            index += 1

            print("{}: Create New Permission".format(index))
            index += 1
            print("{}: Delete Existing Permission".format(index))
            index += 1
            print("{}: Show All Permissions".format(index))
            index += 1
            print("{}: Associate new Operation to Permission".format(index))
            index += 1
            print("{}: Remove Existing Operation from Permission".format(index))
            index += 1

            print("{}: Create New Resource".format(index))
            index += 1
            print("{}: Delete Existing Resource".format(index))
            index += 1
            print("{}: Show All Resources".format(index))
            index += 1

        print("{}: View Assigned Roles".format(index))
        index += 1
        print("{}: Change Password".format(index))
        index += 1
        print("{}: Logout".format(index))
        index += 1
        print("{}: Exit".format(index))

    @classmethod
    def get_data(cls, class_name, input_element):
        retry = 1
        while True:
            if retry < 3:
                element = input('Enter {}:'.format(input_element))
                if class_name.validate(element):
                    break
                print("{} already exist, Try again !!!".format(input_element))
                retry = retry + 1
            else:
                raise Exception("Maximum Retries Reached !!!")

        return element

    @classmethod
    def get_flag(cls, default_flag, message):
        flag = default_flag
        element = input(message)
        if element.lower() in ['y', 'yes', '1', 'true']:
            flag = True
        elif element.lower() in ['n', 'no', '0', 'false']:
            flag = False
        return flag


    @classmethod
    def execute(cls, user, input_selection):
        logout = False
        exit = False
        if not user.is_staff:
            input_selection = int(input_selection) + 18

        # User Operation
        if input_selection == 1:
            # Create User

            username = input('Enter user name:')
            password = rsa.encrypt(getpass.getpass().encode(), publicKey)
            email = input('Enter Email:')
            password_change_required = cls.get_flag(default_flag=True,
                                                    message='Do you want to reset password at '
                                                            'first login (Default is Y) Y/N: ')

            is_staff = cls.get_flag(default_flag=False, message='Is this user Staff user (Default is N) Y/N: ')

            User.create_user(username, password, is_staff, email, password_change_required, [])
            print("{} User Created !!!".format(username))

        if input_selection == 2:
            # Delete User

            email = input('To Delete user, Specify user Email id:')
            deleted_user= User.delete_user(email)
            print("User with email:{} Deleted !!!".format(email))
            logout = True if deleted_user.email == user.email else False

        if input_selection == 3:
            # Get All User
            users = User.get_all_users()
            for user in users:
                print(user)


        if input_selection == 4:
            # associate_new_role_to_user
            print("Type email of user from below list for which you want to add role!!!")
            User.get_all_users()
            email = input('Specify user Email id:')
            rolename = input('Specify New Role names to add (seperated by comma):')
            role_list = list(set(rolename.split(',')))

            User.associate_new_role_to_user(email, role_list)

        if input_selection == 5:
            # remove_role_from_user
            print("Type email of user from below list for which you want to remove role!!!")
            User.get_all_users()
            email = input('Specify user Email id:')
            rolename = input('Specify Role names to remove (seperated by comma):')
            role_list = list(set(rolename.split(',')))

            User.remove_role_from_user(email, role_list)

        # Role Operation
        if input_selection == 6:
            # Create Role
            rolename = input('Enter Role Name:')
            displayname = input('Enter Role display name:')
            customer_modifiable = cls.get_flag(default_flag=False, message='Is this Role Customer modifiable (Default is N) Y/N: ')

            Role.create_role()
            RoleDict[rolename] = RoleData(rolename, displayname, customer_modifiable, user.email, [])

            Role.create_role(user)
        if input_selection == 7:
            # Delete Role
            rolename = input('To Delete role, Specify rolename:')
            role = Role.delete_role(rolename)
            print("Role with rolename:{} Deleted !!!".format(role.rolename))

        if input_selection == 8:
            # Get all Roles
            roles = Role.get_all_roles()
            for role in roles:
                print(role)

        if input_selection == 9:
            # associate_new_permission_to_role
            print("Type rolename from below list for which you want to add permission!!!")
            Role.view_all_roles()
            rolename = input('Specify rolename:')
            permissionname = input('Specify New Permission names to associate (seperated by comma):')
            permission_list = list(set(permissionname.split(',')))

            Role.associate_new_permission_to_role(rolename, permission_list)

        if input_selection == 10:
            # remove_permission_from_role
            print("Type rolename from below list for which you want to remove permission!!!")
            Role.view_all_roles()
            rolename = input('Specify rolename:')
            permissionname = input('Specify Permission names to remove (seperated by comma):')
            permission_list = list(set(permissionname.split(',')))

            Role.remove_permission_from_role(rolename, permission_list)

        # Permission Operation
        if input_selection == 11:
            # Create Permission
            permissionname = input('Enter Permission Name:')
            resource = input('Enter resourcename to associate this permission with:')
            displayname = input('Enter Permission display name:')
            operation = input('Specify Operation (GET,PATCH,DELETE,POST), to associate with '
                              'this permission (seperated by comma):')
            operation_list = list(set(operation.split(',')))
            Permission.create_permission(permissionname, displayname, operation_list, resource, user.email)

        if input_selection == 12:
            # Delete Permission
            permissionname = input('To Delete Permission, Specify permissionname:')

            Role.delete_permission(permissionname)
        if input_selection == 13:
            # Get all Permission
            permissions = Permission.get_all_permissions()
            for permission in permissions:
                print(permission)

        if input_selection == 14:
            # associate_new_operation_to_permission
            print("Type permissionname from below list for which you want to update operation !!!")
            Permission.view_all_permission()
            permissionname = input('Specify Permission name:')
            operation = input(
                'Specify Operation (GET,PATCH,DELETE,POST), to associate with this permission (seperated by comma):')
            operation_list = list(set(operation.split(',')))

            Permission.associate_new_operation_to_permission(permissionname, operation_list)

        if input_selection == 15:
            # remove_operation_from_permission
            print("Type permissionname from below list for which you want to remove operation !!!")
            Permission.view_all_permission()
            permissionname = input('Specify Permission name:')
            operation = input(
                'Specify Operation (GET,PATCH,DELETE,POST), to remove with this permission (seperated by comma):')
            operation_list = list(set(operation.split(',')))

            Permission.remove_operation_from_permission(permissionname, operation_list)

        # Resource Operation
        if input_selection == 16:
            # Create Resource
            resourcename = input('Enter Resource Name:')
            displayname = input('Enter Resource display name:')
            resource = input('Enter Resource api:')
            customer_modifiable = cls.get_flag(default_flag=False,
                                               message='Is this Resource Customer modifiable (Default is N) Y/N: ')
            Resource.create_resource(resourcename, displayname, resource, customer_modifiable, user.email)

        if input_selection == 17:
            # Delete Resource
            resourcename = input('To Delete resource, Specify resourcename:')
            Role.delete_resource(resourcename)

        if input_selection == 18:
            # Get all Resources
            resources = Resource.get_all_resources()
            for resource in resources:
                print(resource)

        # All User Common operation
        if input_selection == 19:
            User.view_assigned_roles(user)
        if input_selection == 20:
            User.change_password(user)
            logout = True
        if input_selection == 21:
            logout = True
        if input_selection == 22:
            logout, exit = True, True
        return logout, exit

def setup():
    # create User
    users = [('admin', admin_password, True, admin_email, False, []),
             ('aman', user_password, False, user_email, True, [])
             ]
    # 'admin@bluestacks.com'
    for u_n, u_p, u_i_s, u_e, u_p_c, u_r in users:
        u_p_e = rsa.encrypt(u_p.encode(), publicKey)
        UserDict[u_e] = UserData(u_n, u_p_e, u_i_s, u_e, u_p_c, u_r)


    # Create Resource
    resourcename = "admin_resource"
    displayname = "Admin Resource"
    customer_modifiable = False
    resource = "api/v1/users"
    ResourceDict[resourcename] = ResourceData(resourcename, displayname, customer_modifiable, resource, admin_email)

    # Create Permission
    permissionname = "default_permission"
    displayname = "Admin Permission"
    PermissionDict[permissionname] = PermissionData(
        permissionname, displayname, [op for op in Permission.Operations], resourcename, admin_email)

    # Create Role
    rolename = "admin_role"
    displayname = "Admin Role"
    customer_modifiable = False
    RoleDict[rolename] = RoleData(rolename, displayname, customer_modifiable, admin_email, [permissionname, ])

    # Update User
    user = UserDict[admin_email]
    UserDict[admin_email] = UserData(user.username, user.password, user.is_staff, admin_email, user.password_change_required, [rolename, ])


def clean_up():

    global ResourceDict, PermissionDict,RoleDict, UserDict
    ResourceDict = {}
    PermissionDict = {}
    RoleDict = {}
    UserDict = {}


def main():
    logout, exit = True, False
    user = None
    setup()
    try:
        while not exit:

            while logout:
                email = input('Enter email:')
                password = rsa.encrypt(getpass.getpass().encode(), publicKey)
                # 1) User Log-in
                user = AuthorizedUser.get_user(email, password)
                if user is not None:
                    logout = False
            # 2) Menu show up
            AuthorizedUser.menu(user)
            input_selection = int(input('Specify your selection:'))

            logout, exit = AuthorizedUser.execute(user, input_selection)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()