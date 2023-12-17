package com.example.securiry.repository;

import com.example.securiry.entity.Role;
import com.example.securiry.entity.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.hibernate.query.NativeQuery;
import org.hibernate.transform.Transformers;
import org.hibernate.type.StandardBasicTypes;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class RoleCustomRepo {
    @PersistenceContext
    private EntityManager entityManager;

//    public List<Role> getRole(User user){
//        StringBuilder sql = new StringBuilder()
//                .append("select r.name as name from users u join users_role ur on u.id = ur.users_id join roles r on r.id = ur.roles_id ");
//        sql.append("where 1=1 ");
//        if(user.getEmail() != null) {
//            sql.append(" and email = :email");
//        }
//
//        NativeQuery<Role> query = ((Session)entityManager.getDelegate()).createNativeQuery(sql.toString());
//
//        if(user.getEmail() != null){
//            query.setParameter("email",user.getEmail());
//        }
//
//        query.addScalar("name", StandardBasicTypes.STRING);
//        query.setResultListTransformer(Transformers.aliasToBean(Role.class));
//        return query.list();
//    }
public List<String> getRoleNames(User user) {
    StringBuilder sql = new StringBuilder()
            .append("select r.name as name from users u join users_role ur on u.id = ur.users_id join roles r on r.id = ur.roles_id ");
    sql.append("where 1=1 ");
    if (user.getEmail() != null) {
        sql.append(" and email = :email");
    }

    NativeQuery<String> query = ((Session) entityManager.getDelegate()).createNativeQuery(sql.toString());

    if (user.getEmail() != null) {
        query.setParameter("email", user.getEmail());
    }

    query.addScalar("name", StandardBasicTypes.STRING);
    return query.list();
}
}
