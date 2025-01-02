# Last Login Date from Int to String Script

This script is designed to convert the int last login to a string and update into custom attributes in Active Directory.

## Prerequisites

Before running the script, ensure the following custom attributes are created in Active Directory:

- `lastLoginString`

Python3 Modules

- ldap3
- winkerberos

### Creating Custom Attributes

You can use the following guide to create these attributes:
[How to create custom attribute in Active Directory and import it to Ivanti Service Manager](https://forums.ivanti.com/s/article/How-to-create-custom-attribute-in-Active-Directory-and-import-it-to-Ivanti-Service-Manager?language=en_US)

**Note:** When following the guide, select **Computer** under classes instead of **User**, and add the attributes to the optional attributes section.

### Making Attributes Viewable in Active Directory Users and Computers

If you want these attributes to be viewable in Active Directory Users and Computers under the **OU** of the computer, refer to the following guide:
[How to Add Additional Columns in Active Directory](https://www.alitajran.com/additional-columns-active-directory/)

## Usage

1. Ensure the custom attributes are created and properly configured.
2. Run the script to insert the last login date time into the specified Active Directory attribute.

---

For further questions or issues, feel free to reach out or refer to the documentation provided in the guides.


