# frozen_string_literal: true

require 'cancan'

module Blacklight
  module AccessControls
    module Ability
      extend ActiveSupport::Concern
      extend Deprecation

      included do
        include CanCan::Ability
        include Blacklight::AccessControls::PermissionsQuery

        # Once you include this module, you can add custom
        # permission methods to ability_logic, like so:
        # self.ability_logic += [:setup_my_permissions]
        class_attribute :ability_logic
        self.ability_logic = %i[discover_permissions read_permissions download_permissions]
      end

      def initialize(user, options = {})
        @current_user = user || guest_user
        @options = options
        @cache = Blacklight::AccessControls::PermissionsCache.new
        grant_permissions
      end

      attr_reader :current_user, :options, :cache

      def self.user_class
        Blacklight::AccessControls.config.user_model.constantize
      end

      # A user who isn't logged in
      def guest_user
        Blacklight::AccessControls::Ability.user_class.new
      end

      def grant_permissions
        Rails.logger.debug('Usergroups are ' + user_groups.inspect)
        ability_logic.each do |method|
          send(method)
        end
      end

      def discover_permissions
        can :discover, String do |id|
          test_discover(id)
        end

        can :discover, SolrDocument do |obj|
          cache.put(obj.id, obj)
          test_discover(obj.id)
        end
      end

      def read_permissions
        # Loading an object from your datastore might be slow (e.g. Fedora), so assume that if a string is passed, it's an object id
        can :read, String do |id|
          test_read(id)
        end

        can :read, SolrDocument do |obj|
          cache.put(obj.id, obj)
          test_read(obj.id)
        end
      end

      def download_permissions
        can :download, String do |id|
          test_download(id)
        end

        can :download, SolrDocument do |obj|
          cache.put(obj.id, obj)
          test_download(obj.id)
        end
      end

      def test_discover(id)
        Deprecation.warn(self, 'Ability#test_discover(id) is deprecated; use #test_access(id, :discover) instead')
        test_access(id, :discover)
      end

      def test_read(id)
        Deprecation.warn(self, 'Ability#test_read(id) is deprecated; use #test_access(id, :read) instead')
        test_access(id, :read)
      end

      def test_download(id)
        Deprecation.warn(self, 'Ability#test_download(id) is deprecated; use #test_access(id, :download) instead')

        test_access(id, :download)
      end

      def test_access(id, access_type)
        Rails.logger.debug("[CANCAN] Checking #{access_type} permissions for user: "\
                           "#{current_user.user_key} with groups: #{user_groups.inspect}")

        if send("#{access_type}_users", id).include?(current_user.user_key)
          return true
        end

        # TODO: when #download_groups stops including groups with only
        # read access (see below), replace #send with #groups_with_access
        (send("#{access_type}_groups", id) & user_groups).present?
      end

      # You can override this method if you are using a different AuthZ (such as LDAP)
      def user_groups
        return @user_groups if @user_groups

        @user_groups = default_user_groups
        @user_groups |= current_user.groups if current_user.respond_to? :groups
        @user_groups |= ['registered'] unless current_user.new_record?
        @user_groups
      end

      # Everyone is automatically a member of group 'public'
      def default_user_groups
        ['public']
      end

      def discover_groups(id)
        Deprecation.warn(self, 'In a future release Ability#discover_groups(id) will no longer include groups with only read or download access')
        # TODO: uncomment when above deprecation takes effect
        # Deprecation.warn(self, 'Ability#read_groups(id) is deprecated; use #groups_with_access(id, :read) instead')
        groups_with_access(id, :discover) | groups_with_access(id, :read) | groups_with_access(id, :download)
      end

      def discover_users(id)
        Deprecation.warn(self, 'In a future release Ability#discover_users(id) will no longer include users with only read or download access')
        # Deprecation.warn(self, 'Ability#read_users(id) is deprecated; use #users_with_access(id, :read) instead')
        users_with_access(id, :discover) | users_with_access(id, :read) | users_with_access(id, :download)
      end

      def read_groups(id)
        Deprecation.warn(self, 'In a future release Ability#read_groups(id) will no longer include groups with only download access')
        # Deprecation.warn(self, 'Ability#read_groups(id) is deprecated; use #groups_with_access(id, :read) instead')
        groups_with_access(id, :read) | groups_with_access(id, :download)
      end

      def read_users(id)
        Deprecation.warn(self, 'In a future release Ability#read_users(id) will no longer include users with only download access')
        # Deprecation.warn(self, 'Ability#read_users(id) is deprecated; use #users_with_access(id, :read) instead')
        users_with_access(id, :download) | users_with_access(id, :read)
      end

      def download_users(id)
        # Deprecation.warn(self, 'Ability#download_users(id) is deprecated; use #users_with_access(id, :download) instead')
        users_with_access(id, :download)
      end

      def download_groups(id)
        # Deprecation.warn(self, 'Ability#download_groups(id) is deprecated; use #groups_with_access(id, :download) instead')
        groups_with_access(id, :download)
      end

      def users_with_access(id, access_type)
        doc = permissions_doc(id)
        return [] if doc.nil?
        users = Array(doc[self.class.send("#{access_type}_user_field")])
        Rails.logger.debug("[CANCAN] users with #{access_type} access: #{users.inspect}")
        users
      end

      def groups_with_access(id, access_type)
        doc = permissions_doc(id)
        return [] if doc.nil?
        groups = Array(doc[self.class.send("#{access_type}_group_field")])
        Rails.logger.debug("[CANCAN] groups with #{access_type} access: #{groups.inspect}")
        groups
      end

      module ClassMethods
        def discover_group_field
          Blacklight::AccessControls.config.discover_group_field
        end

        def discover_user_field
          Blacklight::AccessControls.config.discover_user_field
        end

        def read_group_field
          Blacklight::AccessControls.config.read_group_field
        end

        def read_user_field
          Blacklight::AccessControls.config.read_user_field
        end

        def download_group_field
          Blacklight::AccessControls.config.download_group_field
        end

        def download_user_field
          Blacklight::AccessControls.config.download_user_field
        end
      end
    end
  end
end
