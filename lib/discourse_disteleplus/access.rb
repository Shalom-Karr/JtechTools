# frozen_string_literal: true

module DiscourseDisteleplus
  module Access
    def self.allowed_group_ids
      ids = SiteSetting.disteleplus_allowed_groups_map
      ids = SiteSetting.disteleplus_allowed_groups.to_s.split("|").map(&:to_i) if ids.blank?
      ids.map(&:to_i).reject(&:zero?).uniq
    end

    def self.allowed?(user)
      return false unless SiteSetting.disteleplus_enabled
      return false if user.nil? || !user.active || user.staged || user.suspended?
      return true if user.admin?

      (user.group_ids & allowed_group_ids).any?
    end

    # Admins always moderate; other staff only when the operator has put the
    # staff group into disteleplus_allowed_groups. A moderator being inside a
    # broad group like trust_level_1 must not grant moderation.
    def self.moderator?(user)
      return false unless user&.staff? && allowed?(user)
      user.admin? || allowed_group_ids.include?(Group::AUTO_GROUPS[:staff])
    end

    def self.allowed_users
      group_user_ids = GroupUser.where(group_id: allowed_group_ids).select(:user_id)
      User
        .real
        .activated
        .not_suspended
        .not_silenced
        .where(staged: false)
        .where("users.admin OR users.id IN (?)", group_user_ids)
        .distinct
    end

    def self.can_edit?(user, message)
      return false unless allowed?(user) && message&.source_discourse? && !message.deleted?
      message.user_id == user.id || moderator?(user)
    end

    def self.can_delete?(user, message)
      can_edit?(user, message)
    end
  end
end
